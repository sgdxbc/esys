use std::{
    collections::{BTreeMap, HashMap},
    mem::{replace, take},
    ops::{ControlFlow, RangeInclusive},
    sync::Mutex,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::{base::BaseEvent, rpc::proto};
use esys_wirehair::{WirehairDecoder, WirehairEncoder};
use libp2p::{
    identity::{Keypair, PublicKey},
    kad::kbucket,
    multihash::{Code, Hasher, Multihash, MultihashDigest, Sha2_256},
    request_response::{Message, ResponseChannel},
    swarm::{NetworkBehaviour as NetworkBehavior, SwarmEvent::Behaviour as Behavior},
    Multiaddr, PeerId,
};
use rand::{random, rngs::StdRng, thread_rng, Rng, RngCore, SeedableRng};
use tokio::{spawn, sync::mpsc, time::sleep};

use crate::base::BaseHandle;

pub struct App {
    base: BaseHandle,
    control: (
        mpsc::UnboundedSender<AppEvent>,
        mpsc::UnboundedReceiver<AppEvent>,
    ),

    keypair: Keypair,
    addr: Multiaddr,

    chunks: HashMap<Multihash, Chunk>,

    client_chunks: HashMap<Multihash, ClientChunk>,
    put_chunks: Option<mpsc::UnboundedSender<Multihash>>,

    config: AppConfig,
}

pub struct AppControl(mpsc::UnboundedSender<AppEvent>);

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub invite_count: usize,
    pub chunk_k: usize,
    pub chunk_n: usize,
    pub fragment_k: usize,
    pub fragment_n: usize,
    pub fragment_size: usize,
    pub watermark_interval: Duration,
    pub membership_interval: Duration,
    pub gossip_interval: Duration,
    pub invite_interval: Duration,
}

#[derive(Debug)]
struct Chunk {
    fragment_index: u32,
    fragment: Fragment,
    members: HashMap<PeerId, Member>,
    indexes: BTreeMap<u32, PublicKey>,
    // verified but not yet gossip, so not sure whether it has a fragment available already
    // not send to invited nodes to prevent fetch fragment from a premature member
    joining_members: HashMap<PeerId, (PublicKey, Member)>,

    enter_time_sec: u64,
    // expiration duration
    high_watermark: u32,
}

#[derive(Debug, Clone)]
struct Member {
    index: u32,
    addr: Multiaddr,
    proof: Vec<u8>,
    alive: bool,
}

#[derive(Debug)]
enum Fragment {
    Incomplete(Mutex<WirehairDecoder>),
    Complete(Vec<u8>),
}

struct ClientChunk {
    encoder: Mutex<WirehairEncoder>,
    enter_time_sec: u64,
    index: u32,
    members: HashMap<PeerId, (Member, ResponseChannel<proto::Response>)>,
    indexes: BTreeMap<u32, PublicKey>,
}

#[derive(Debug)]
enum AppEvent {
    Close,

    Rpc(<crate::rpc::Behavior as NetworkBehavior>::OutEvent),
    Gossip(Multihash),
    Membership(Multihash),
    Invite(Multihash),

    ClientInvite,
    ClientPut(mpsc::UnboundedSender<Multihash>),
}

impl AppControl {
    pub fn close(&self) {
        self.0.send(AppEvent::Close).unwrap();
    }

    pub fn put(&self) -> mpsc::UnboundedReceiver<Multihash> {
        let channel = mpsc::unbounded_channel();
        self.0.send(AppEvent::ClientPut(channel.0)).unwrap();
        channel.1
    }
}

impl App {
    pub fn new(base: BaseHandle, keypair: Keypair, addr: Multiaddr, config: AppConfig) -> Self {
        Self {
            base,
            control: mpsc::unbounded_channel(),
            chunks: Default::default(),
            client_chunks: Default::default(),
            put_chunks: None,
            addr,
            keypair,
            config,
        }
    }

    pub fn control(&self) -> AppControl {
        AppControl(self.control.0.clone())
    }

    pub async fn serve(&mut self) {
        let control = self.control.0.clone();
        let s = self.base.subscribe(move |event, _| {
            match event.take().unwrap() {
                Behavior(BaseEvent::Rpc(event)) => {
                    if control.send(AppEvent::Rpc(event)).is_err() {
                        return ControlFlow::Break(());
                    }
                }
                other_event => {
                    *event = Some(other_event);
                }
            }
            ControlFlow::Continue(())
        });
        drop(s);

        while let Some(event) = self.control.1.recv().await {
            use proto::{request::Inner::*, response::Inner::*};
            match event {
                AppEvent::Close => break,

                AppEvent::Gossip(chunk_hash) => self.gossip(&chunk_hash),
                AppEvent::Membership(chunk_hash) => self.check_membership(&chunk_hash),
                AppEvent::Invite(chunk_hash) => self.invite(&chunk_hash),

                AppEvent::Rpc(libp2p::request_response::Event::Message {
                    message:
                        Message::Request {
                            request, channel, ..
                        },
                    ..
                }) => match request.inner.unwrap() {
                    Gossip(message) => self.handle_gossip(&message), // no response
                    Invite(message) => self.handle_invite(&message), // no response
                    QueryFragment(message) => self.handle_query_fragment(&message, channel),
                    QueryProof(message) => self.handle_query_proof(&message, channel),
                },
                AppEvent::Rpc(libp2p::request_response::Event::Message {
                    message: Message::Response { response, .. },
                    ..
                }) => match response.inner.unwrap() {
                    QueryFragmentOk(message) => self.handle_query_fragment_ok(&message),
                    QueryProofOk(message) => self.handle_query_proof_ok(&message),
                },
                AppEvent::Rpc(_) => {} // do anything?

                AppEvent::ClientInvite => self.client_invite(),
                AppEvent::ClientPut(channel) => {
                    assert!(self.put_chunks.is_none());
                    self.put_chunks = Some(channel);
                    let mut data = vec![
                        0;
                        self.config.fragment_size
                            * self.config.fragment_k
                            * self.config.chunk_k
                    ];
                    thread_rng().fill_bytes(&mut data);
                    self.put(&data);
                }
            }
        }
    }

    fn set_timer(&self, duration: Duration, event: AppEvent) {
        let control = self.control.0.clone();
        spawn(async move {
            sleep(duration).await;
            let _ = control.send(event); // could fail if outlive event loop
        });
    }

    fn put(&mut self, data: &[u8]) {
        assert!(self.client_chunks.is_empty());
        assert_eq!(
            data.len(),
            self.config.fragment_size * self.config.fragment_k * self.config.chunk_k
        );
        let mut outer_encoder = WirehairEncoder::new(
            data,
            (self.config.fragment_size * self.config.fragment_k) as _,
        );
        let mut buffer = vec![0; self.config.fragment_size * self.config.fragment_k];
        for _ in 0..self.config.chunk_n {
            outer_encoder.encode(random(), &mut buffer).unwrap();
            let chunk_hash = Code::Sha2_256.digest(&buffer);
            let chunk = ClientChunk {
                encoder: Mutex::new(WirehairEncoder::new(
                    &buffer,
                    self.config.fragment_size as _,
                )),
                enter_time_sec: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                index: 0,
                members: Default::default(),
                indexes: Default::default(),
            };
            self.client_chunks.insert(chunk_hash, chunk);
        }
        self.client_invite();
    }

    fn client_invite(&mut self) {
        for (chunk_hash, chunk) in &mut self.client_chunks {
            assert!(chunk.indexes.len() < self.config.fragment_n);
            chunk.index += (self.config.fragment_n - chunk.indexes.len()) as u32;
            tracing::debug!(chunk = ?chunk_hash, index = ?(0..chunk.index), "invite");
            for index in 0..chunk.index {
                if chunk.indexes.contains_key(&index) {
                    continue;
                }
                let request = proto::Request::from(proto::Invite {
                    chunk_hash: chunk_hash.to_bytes(),
                    fragment_index: index,
                    enter_time_sec: chunk.enter_time_sec,
                    members: vec![proto::Member::new(
                        u32::MAX,
                        &self.keypair.public(),
                        &self.addr,
                        Default::default(),
                    )],
                });
                spawn(Self::invite_index_task(
                    Self::fragment_hash(chunk_hash, index),
                    self.base.clone(),
                    self.config.invite_count,
                    request,
                    PeerId::from_public_key(&self.keypair.public()),
                ));
            }
        }

        self.set_timer(self.config.invite_interval, AppEvent::ClientInvite);
    }

    fn client_handle_query_fragment(
        &mut self,
        message: &proto::QueryFragment,
        channel: ResponseChannel<proto::Response>,
    ) {
        let chunk_hash = message.chunk_hash();
        let member = message.member.as_ref().unwrap();
        let public_key = member.public_key().unwrap();
        if !self.verify(&chunk_hash, member.index, &public_key, &member.proof) {
            //
            return;
        }

        let chunk = self.client_chunks.get_mut(&chunk_hash).unwrap();
        let member_id = PeerId::from_public_key(&public_key);
        // check duplicated index / member
        // a little bit duplicated with the last part of this file but i don't care any more
        if chunk.members.contains_key(&member_id) {
            tracing::debug!(chunk = ?chunk_hash, id = %member_id, "same member multiple indexes");
            return;
        }
        if let Some(prev_key) = chunk.indexes.get(&member.index) {
            tracing::debug!(chunk = ?chunk_hash, index = member.index, "same index multiple members");
            let d = |peer_id: &PeerId| {
                kbucket::Key::from(peer_id.to_bytes()).distance(&kbucket::Key::from(chunk_hash))
            };
            let prev_id = PeerId::from_public_key(prev_key);
            if d(&prev_id) <= d(&member_id) {
                return;
            }
            chunk.members.remove(&prev_id);
        }
        tracing::debug!(chunk = ?chunk_hash, index = member.index, id = %member_id, "insert member");
        chunk.indexes.insert(member.index, public_key);
        chunk
            .members
            .insert(member_id, (Member::new(member, false), channel));

        if chunk.indexes.len() >= self.config.fragment_n {
            tracing::debug!(chunk = ?chunk_hash, "finalize put");
            let mut chunk = self.client_chunks.remove(&chunk_hash).unwrap();
            let members = Vec::from_iter(chunk.members.values_mut().map(|(member, _)| {
                proto::Member::new(
                    member.index,
                    &chunk.indexes[&member.index],
                    &member.addr,
                    take(&mut member.proof), // not used any more
                )
            }));
            for (member, channel) in chunk.members.into_values() {
                let mut fragment = vec![0; self.config.fragment_size];
                chunk
                    .encoder
                    .get_mut()
                    .unwrap()
                    .encode(member.index, &mut fragment)
                    .unwrap();
                let response = proto::Response::from(proto::QueryFragmentOk {
                    chunk_hash: chunk_hash.to_bytes(),
                    member: None,
                    fragment,
                    init_members: members.clone(),
                });
                self.base.ingress(move |swarm| {
                    swarm
                        .behaviour_mut()
                        .rpc
                        .send_response(channel, response)
                        .unwrap();
                });
            }

            self.put_chunks.as_ref().unwrap().send(chunk_hash).unwrap();
            if self.client_chunks.is_empty() {
                self.put_chunks = None;
            }
        }
    }

    // entropy message flow
    // precondition: a group of peers that hold identical `members` view
    // invariant: every peer in `members` can be queried for one fragment
    // 1. some group member INVITE a new peer, with current `members`
    // 2. if the new peer proves itself, it broadcasts QUERY_FRAGMENT to `members`
    // 3. sufficient peers from `members` verify the new peer's proof and reply QUERY_FRAGMENT_OK with local fragment
    // 4. new peer finish recovering and generating its fragment, broadcast GOSSIP to `members`
    // 5. `members` peers insert the new peer into local `members` view, start to GOSSIP to the new peer
    //   5.1. if a member peer has not received the new peer's proof upon heard about the new peer, it sends QUERY_PROOF
    //   to new peer and insert the new peer into local `members` when receiving QUERY_PROOF_OK
    //
    // how to INVITE
    // on invite timer
    // 1. update members' liveness knowledge base on received GOSSIP
    // 2. in range `low_watermark..<highest taken fragment index>`, INVITE on every index that is not taken
    // 3. keep INVITE on increamentally even higher fragment index until sufficient fragment indexes are taken by unique
    // members
    // 4. (after all INVITE done) reset <highest taken fragment index> to the `group_size`th lowest taken fragment index
    // (above low watermark)

    fn check_membership(&mut self, chunk_hash: &Multihash) {
        let chunk = self.chunks.get_mut(chunk_hash).unwrap();
        chunk.retain_alive(&self.config);
        for member in chunk.members.values_mut() {
            member.alive = false;
        }
        if !chunk
            .members
            .contains_key(&PeerId::from_public_key(&self.keypair.public()))
        {
            self.chunks.remove(chunk_hash);
            return;
        }

        assert!(chunk.fragment_count() >= self.config.fragment_k);
        self.invite(chunk_hash);
        self.set_timer(
            self.config.membership_interval,
            AppEvent::Membership(*chunk_hash),
        );
    }

    fn invite(&mut self, chunk_hash: &Multihash) {
        let chunk = self.chunks.get_mut(chunk_hash).unwrap();
        // can it get larger then n?
        if chunk.fragment_count() >= self.config.fragment_n {
            return;
        }

        // assume no more node below high watermark is avaiable i.e. can be successfully invited any more
        chunk.high_watermark += (self.config.fragment_n - chunk.fragment_count()) as u32;
        let invite_indexes = Vec::from_iter(
            chunk
                .watermark(&self.config)
                .filter(|index| !chunk.indexes.contains_key(index)),
        );
        for index in invite_indexes {
            self.invite_index(chunk_hash, index);
        }
        self.set_timer(self.config.invite_interval, AppEvent::Invite(*chunk_hash));
    }

    fn gossip(&self, chunk_hash: &Multihash) {
        let Some(chunk) = self.chunks.get(chunk_hash) else {
            // e.g. go below low watermark and get removed in membership timer
            return;
        };
        let request = proto::Request::from(proto::Gossip {
            chunk_hash: chunk_hash.to_bytes(),
            fragment_index: chunk.fragment_index,
            members: chunk
                .members
                .values()
                .map(|member| {
                    proto::Member::new_trustless(
                        member.index,
                        &chunk.indexes[&member.index],
                        &member.addr,
                    )
                })
                .collect(),
        });
        for (&peer_id, member) in &chunk.members {
            if peer_id == PeerId::from_public_key(&self.keypair.public()) {
                continue;
            }
            let peer_addr = member.addr.clone();
            let request = request.clone();
            self.base.ingress(move |swarm| {
                swarm
                    .behaviour_mut()
                    .rpc_ensure_address(&peer_id, peer_addr);
                swarm.behaviour_mut().rpc.send_request(&peer_id, request);
            });
        }
        self.set_timer(self.config.gossip_interval, AppEvent::Gossip(*chunk_hash));
    }

    fn handle_gossip(&mut self, message: &proto::Gossip) {
        let chunk_hash = message.chunk_hash();
        let Some(chunk) = self.chunks.get_mut(&chunk_hash) else {
            //
            return;
        };
        for member in &message.members {
            if !chunk.watermark(&self.config).contains(&member.index) {
                continue;
            }
            if let Some(local_member) = chunk.members.get_mut(&member.id()) {
                if local_member.index == message.fragment_index {
                    local_member.alive = true;
                }
            } else if let Some((public_key, mut joining_member)) =
                chunk.joining_members.remove(&member.id())
            {
                joining_member.alive = true;
                // it is possible that this `insert` evict local peer itself from the group
                // later this will cause removing chunk when check membership, so no special treatment here
                // same for the `insert` in handling QueryProofOk
                chunk.insert(&chunk_hash, public_key, joining_member, &self.config);
                chunk.retain_alive(&self.config); // shrink high watermark if possible
            } else if chunk.will_accept(&chunk_hash, member.index, &member.id(), &self.config) {
                // this is also the path for receiving gossip from unseen peer
                // because the gossip always include sender itself in the `members`
                let peer_id = member.id();
                let addr = member.addr();
                let request = proto::Request::from(proto::QueryProof {
                    chunk_hash: message.chunk_hash.clone(),
                });
                self.base.ingress(move |swarm| {
                    swarm.behaviour_mut().rpc_ensure_address(&peer_id, addr);
                    swarm.behaviour_mut().rpc.send_request(&peer_id, request);
                });
            }
        }
    }

    fn invite_index(&self, chunk_hash: &Multihash, index: u32) {
        let chunk = &self.chunks[chunk_hash];
        assert!(!chunk.indexes.contains_key(&index));
        assert!(chunk.watermark(&self.config).contains(&index));

        let request = proto::Request::from(proto::Invite {
            chunk_hash: chunk_hash.to_bytes(),
            fragment_index: index,
            enter_time_sec: chunk.enter_time_sec,
            members: chunk
                .members
                .values()
                .map(|member| {
                    proto::Member::new_trustless(
                        member.index,
                        &chunk.indexes[&member.index],
                        &member.addr,
                    )
                })
                .collect(),
        });
        spawn(Self::invite_index_task(
            Self::fragment_hash(chunk_hash, index),
            self.base.clone(),
            self.config.invite_count,
            request,
            PeerId::from_public_key(&self.keypair.public()),
        ));
    }

    async fn invite_index_task(
        fragment_hash: Multihash,
        base: BaseHandle,
        invite_count: usize,
        request: proto::Request,
        local_id: PeerId,
    ) {
        for (peer_id, peer_addr) in base.query(fragment_hash, invite_count).await {
            // if chunk.members.contains_key(&peer_id) {
            //     continue;
            // }
            //
            // skip this check may cause some member to be re-invited (with low probability hopefully)
            // which will be ignored by honest members, and a faulty member may try duplicated join anyway regardless
            // of this inviting (and will be rejected), so it's fine
            //
            // however, should we filter out `joining_memebers` in some way?

            if peer_id == local_id {
                continue;
            }
            let Some(peer_addr) = peer_addr else {
                continue;
            };

            let request = request.clone();
            base.ingress(move |swarm| {
                swarm
                    .behaviour_mut()
                    .rpc_ensure_address(&peer_id, peer_addr);
                swarm.behaviour_mut().rpc.send_request(&peer_id, request);
            });
        }
    }

    fn handle_invite(&mut self, message: &proto::Invite) {
        let chunk_hash = message.chunk_hash();
        tracing::debug!(chunk = ?chunk_hash, "invited");
        if self.chunks.contains_key(&chunk_hash) {
            return; // need merge?
        }

        let Some(proof) = self.prove(&chunk_hash, message.fragment_index) else {
            tracing::debug!(chunk = ?chunk_hash, index = message.fragment_index, "not selected");
            return;
        };

        assert!(message.members.len() >= self.config.fragment_k);
        // however we are not sure whether it is valid even after this assert = =

        let mut chunk = Chunk {
            fragment_index: message.fragment_index,
            fragment: Fragment::Incomplete(Mutex::new(WirehairDecoder::new(
                (self.config.fragment_size * self.config.fragment_k) as _,
                self.config.fragment_size as _,
            ))),
            members: Default::default(),
            indexes: Default::default(),
            joining_members: Default::default(),
            enter_time_sec: message.enter_time_sec,
            high_watermark: message
                .members
                .iter()
                .map(|member| member.index)
                .chain([message.fragment_index].into_iter())
                .max()
                .unwrap(),
        };

        let inserted = chunk.insert(
            &chunk_hash,
            self.keypair.public(),
            Member {
                index: chunk.fragment_index,
                addr: self.addr.clone(),
                proof: proof.clone(),
                alive: true,
            },
            &self.config,
        );
        assert!(inserted);
        self.chunks.insert(chunk_hash, chunk);

        // do we really don't need to retry the following?
        tracing::debug!(chunk = ?chunk_hash, index = message.fragment_index, "query fragment");
        let request = proto::Request::from(proto::QueryFragment {
            chunk_hash: message.chunk_hash.clone(),
            member: Some(proto::Member::new(
                message.fragment_index,
                &self.keypair.public(),
                &self.addr,
                proof,
            )),
        });
        for member in &message.members {
            let peer_id = member.id();
            let addr = member.addr();
            let request = request.clone();
            self.base.ingress(move |swarm| {
                swarm.behaviour_mut().rpc_ensure_address(&peer_id, addr);
                swarm.behaviour_mut().rpc.send_request(&peer_id, request);
            });
        }
    }

    fn handle_query_fragment(
        &mut self,
        message: &proto::QueryFragment,
        channel: ResponseChannel<proto::Response>,
    ) {
        let chunk_hash = message.chunk_hash();
        if self.client_chunks.contains_key(&chunk_hash) {
            return self.client_handle_query_fragment(message, channel);
        }
        if !self.chunks.contains_key(&chunk_hash) {
            tracing::debug!(chunk = ?chunk_hash, "query fragment on missing chunk");
            return;
        }

        let member = message.member.as_ref().unwrap();
        let public_key = member.public_key().unwrap();
        if !self.verify(&chunk_hash, member.index, &public_key, &member.proof) {
            //
            return;
        }

        let chunk = self.chunks.get_mut(&chunk_hash).unwrap();
        chunk.joining_members.insert(
            PeerId::from_public_key(&public_key),
            (public_key, Member::new(member, false)),
        );

        let Fragment::Complete(fragment) = &chunk.fragment else {
            panic!("receive query fragment before sending gossip")
        };
        let response = proto::Response::from(proto::QueryFragmentOk {
            chunk_hash: message.chunk_hash.clone(),
            fragment: fragment.clone(),
            member: Some(proto::Member::new(
                chunk.fragment_index,
                &self.keypair.public(),
                &self.addr,
                chunk.members[&PeerId::from_public_key(&self.keypair.public())]
                    .proof
                    .clone(),
            )),
            init_members: Default::default(), // not used
        });
        self.base.ingress(move |swarm| {
            swarm
                .behaviour_mut()
                .rpc
                .send_response(channel, response)
                .unwrap();
        });
    }

    fn handle_query_fragment_ok(&mut self, message: &proto::QueryFragmentOk) {
        let chunk_hash = message.chunk_hash();
        if !self.chunks.contains_key(&chunk_hash) {
            //
            return;
        };

        let Some(member) = &message.member else {
            // sent from client
            let chunk = self.chunks.get_mut(&chunk_hash).unwrap();
            chunk.fragment = Fragment::Complete(message.fragment.clone());
            for member in &message.init_members {
                chunk.insert(&chunk_hash, member.public_key().unwrap(), Member::new(member, true), &self.config);
            }
            self.set_timer(thread_rng().gen_range(Duration::ZERO..self.config.gossip_interval), AppEvent::Gossip(chunk_hash));
            self.set_timer(thread_rng().gen_range(Duration::ZERO..self.config.membership_interval), AppEvent::Membership(chunk_hash));
            return;
        };

        let public_key = member.public_key().unwrap();
        if !self.verify(&chunk_hash, member.index, &public_key, &member.proof) {
            //
            return;
        }

        let chunk = self.chunks.get_mut(&chunk_hash).unwrap();
        // unconditionally insert members that are queried previously
        // mostly for simplifying stuff, and should not break anything
        chunk.members.insert(
            PeerId::from_public_key(&public_key),
            Member::new(member, true),
        );
        chunk.indexes.insert(member.index, public_key);

        let Fragment::Incomplete(decoder) = &mut chunk.fragment else {
            //
            return;
        };

        let recovered = decoder
            .get_mut()
            .unwrap()
            .decode(member.index, &message.fragment)
            .unwrap();
        if !recovered {
            return;
        }

        // replace with a placeholder
        let Fragment::Incomplete(decoder) =
            replace(&mut chunk.fragment, Fragment::Complete(Default::default()))
        else {
            unreachable!()
        };
        let mut fragment = vec![0; self.config.fragment_size];
        decoder
            .into_inner()
            .unwrap()
            .into_encoder()
            .unwrap()
            .encode(chunk.fragment_index, &mut fragment)
            .unwrap();
        let _ = replace(&mut chunk.fragment, Fragment::Complete(fragment));

        // immediately check membership before sending first gossip?
        self.gossip(&chunk_hash);
        // randomize first membership checking delay to (hopefully) avoid duplicated invitation
        // all members are marked alive on insertion, so no need to add another full membership interval
        self.set_timer(
            thread_rng().gen_range(Duration::ZERO..self.config.membership_interval),
            AppEvent::Membership(chunk_hash),
        );
    }

    pub fn handle_query_proof(
        &self,
        message: &proto::QueryProof,
        channel: ResponseChannel<proto::Response>,
    ) {
        let Some(chunk) = self.chunks.get(&message.chunk_hash()) else {
            //
            return;
        };
        let local_key = self.keypair.public();
        let response = proto::Response::from(proto::QueryProofOk {
            chunk_hash: message.chunk_hash.clone(),
            member: Some(proto::Member::new(
                chunk.fragment_index,
                &local_key,
                &self.addr,
                chunk.members[&PeerId::from_public_key(&local_key)]
                    .proof
                    .clone(),
            )),
        });
        self.base.ingress(move |swarm| {
            swarm
                .behaviour_mut()
                .rpc
                .send_response(channel, response)
                .unwrap();
        });
    }

    pub fn handle_query_proof_ok(&mut self, message: &proto::QueryProofOk) {
        let chunk_hash = message.chunk_hash();
        if !self.chunks.contains_key(&chunk_hash) {
            //
            return;
        }
        let member = message.member.as_ref().unwrap();
        let public_key = member.public_key().unwrap();
        if !self.verify(&chunk_hash, member.index, &public_key, &member.proof) {
            //
            return;
        }
        let chunk = self.chunks.get_mut(&chunk_hash).unwrap();
        chunk.insert(
            &chunk_hash,
            public_key,
            Member::new(member, true),
            &self.config,
        );
        chunk.retain_alive(&self.config); // shrink high watermark if possible
    }

    // TODO homomorphic hashing
    fn fragment_hash(chunk_hash: &Multihash, index: u32) -> Multihash {
        let mut input = chunk_hash.to_bytes();
        input.extend(&index.to_be_bytes());
        Code::Sha2_256.digest(&input)
    }

    fn accept_probablity(chunk_hash: &Multihash, index: u32, peer_id: &PeerId) -> f64 {
        let fragment_hash = Self::fragment_hash(chunk_hash, index);
        let distance = kbucket::Key::from(fragment_hash).distance(&kbucket::Key::from(*peer_id));
        // TODO tune the probability distribution properly
        // match distance.ilog2() {
        //     None => 0.95,
        //     Some(i) if i <= 18 => 0.9 - 0.05 * i as f64,
        //     _ => 0.,
        // }
        1.
    }

    fn accepted(chunk_hash: &Multihash, index: u32, peer_id: &PeerId, proof: &[u8]) -> bool {
        let seed = {
            let mut hasher = Sha2_256::default();
            hasher.update(proof);
            hasher.finalize().try_into().unwrap()
        };
        StdRng::from_seed(seed).gen_bool(Self::accept_probablity(chunk_hash, index, peer_id))
    }

    fn prove(&self, chunk_hash: &Multihash, index: u32) -> Option<Vec<u8>> {
        let proof = {
            let mut input = chunk_hash.to_bytes();
            input.extend(&index.to_be_bytes());
            self.keypair.sign(&input).unwrap()
        };
        if Self::accepted(
            chunk_hash,
            index,
            &PeerId::from_public_key(&self.keypair.public()),
            &proof,
        ) {
            Some(proof)
        } else {
            None
        }
    }

    fn verify(
        &self,
        chunk_hash: &Multihash,
        index: u32,
        public_key: &PublicKey,
        proof: &[u8],
    ) -> bool {
        let mut input = chunk_hash.to_bytes();
        input.extend(&index.to_be_bytes());
        let chunk = &self.chunks[chunk_hash];
        chunk.watermark(&self.config).contains(&index)
            && public_key.verify(&input, proof)
            && Self::accepted(
                chunk_hash,
                index,
                &PeerId::from_public_key(public_key),
                proof,
            )
    }
}

impl Chunk {
    fn low_watermark(&self, config: &AppConfig) -> u32 {
        ((SystemTime::now().duration_since(UNIX_EPOCH).unwrap()
            - Duration::from_secs(self.enter_time_sec))
        .as_secs()
            / config.watermark_interval.as_secs()) as _
    }

    fn watermark(&self, config: &AppConfig) -> RangeInclusive<u32> {
        self.low_watermark(config)..=self.high_watermark
    }

    fn fragment_count(&self) -> usize {
        self.indexes.len()
    }

    fn retain_alive(&mut self, config: &AppConfig) {
        let watermark = self.watermark(config);
        let mut members = take(&mut self.members);
        let indexes = take(&mut self.indexes);
        let mut alive_count = 0;
        for (index, public_key) in indexes {
            let peer_id = PeerId::from_public_key(&public_key);
            if !watermark.contains(&index) || members[&peer_id].index != index {
                continue;
            };
            // if a member show up for multiple indexes, it should be removed for the lowest index among those, and
            // high indexes will be released here
            let Some(member) = members.remove(&peer_id) else {
                continue;
            };
            if !member.alive {
                continue;
            }
            self.indexes.insert(index, public_key.clone());
            self.members.insert(peer_id, member);
            alive_count += 1;

            // all higher indexes are released, shrinking the high watermark
            if alive_count == config.fragment_n {
                self.high_watermark = index;
                break;
            }
        }
    }

    fn will_accept(
        &self,
        chunk_hash: &Multihash,
        index: u32,
        peer_id: &PeerId,
        config: &AppConfig,
    ) -> bool {
        if !self.watermark(config).contains(&index) {
            return false;
        }
        let Some(member_key) = self.indexes.get(&index) else {
            return true;
        };
        let d = |peer_id: &PeerId| {
            kbucket::Key::from(peer_id.to_bytes()).distance(&kbucket::Key::from(*chunk_hash))
        };
        // check member exist?
        d(peer_id) < d(&PeerId::from_public_key(member_key))
    }

    fn insert(
        &mut self,
        chunk_hash: &Multihash,
        public_key: PublicKey,
        member: Member,
        config: &AppConfig,
    ) -> bool {
        assert!(member.alive);
        // assert will accept?
        if !self.will_accept(
            chunk_hash,
            member.index,
            &PeerId::from_public_key(&public_key),
            config,
        ) {
            return false;
        }
        let index = member.index;
        self.members
            .insert(PeerId::from_public_key(&public_key), member);
        self.indexes.insert(index, public_key);
        true
    }
}

impl Member {
    fn new(member: &proto::Member, alive: bool) -> Self {
        Self {
            index: member.index,
            addr: member.addr(),
            proof: member.proof.clone(),
            alive,
        }
    }
}
