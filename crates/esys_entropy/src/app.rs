use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    mem::{replace, take},
    ops::{ControlFlow, Range},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::{base::BaseEvent, rpc::proto};
use esys_wirehair::{WirehairDecoder, WirehairEncoder};
use libp2p::{
    identity::{Keypair, PublicKey},
    kad::kbucket,
    multihash::{Code, Hasher, Multihash, MultihashDigest, Sha2_256},
    request_response::{Message, OutboundFailure, ResponseChannel},
    swarm::{NetworkBehaviour as NetworkBehavior, SwarmEvent::Behaviour as Behavior},
    Multiaddr, PeerId,
};
use rand::{random, rngs::StdRng, thread_rng, Rng, SeedableRng};
use tokio::{
    spawn,
    sync::{mpsc, Semaphore},
    task::spawn_blocking,
    time::sleep,
};
use tracing::Instrument;

use crate::base::BaseHandle;

pub struct App {
    pub base: BaseHandle,
    control: (
        mpsc::UnboundedSender<AppEvent>,
        mpsc::UnboundedReceiver<AppEvent>,
    ),

    keypair: Keypair,
    addr: Multiaddr,

    chunks: HashMap<Multihash, Chunk>,
    invite_resource: Arc<Semaphore>,

    client_chunks: HashMap<Multihash, ClientChunk>,
    client_queue: VecDeque<Multihash>,
    put_chunks: Option<mpsc::UnboundedSender<(u32, Multihash, HashMap<PeerId, Member>)>>,
    get_chunks: HashMap<Multihash, mpsc::UnboundedSender<(u32, Vec<u8>)>>,

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
pub struct Member {
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
    chunk_index: u32,
    encoder: WirehairEncoder,
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

    ClientInvite(Multihash),
    ClientPut(
        Vec<u8>,
        mpsc::UnboundedSender<(u32, Multihash, HashMap<PeerId, Member>)>,
    ),
    ClientGetWithMembers(
        Multihash,
        HashMap<PeerId, Member>,
        mpsc::UnboundedSender<(u32, Vec<u8>)>,
    ),
}

impl AppControl {
    pub fn close(&self) {
        self.0.send(AppEvent::Close).unwrap();
    }

    pub fn put(
        &self,
        data: Vec<u8>,
    ) -> mpsc::UnboundedReceiver<(u32, Multihash, HashMap<PeerId, Member>)> {
        let channel = mpsc::unbounded_channel();
        self.0.send(AppEvent::ClientPut(data, channel.0)).unwrap();
        channel.1
    }

    pub fn get_with_members(
        &self,
        chunk_hash: &Multihash,
        members: HashMap<PeerId, Member>,
    ) -> mpsc::UnboundedReceiver<(u32, Vec<u8>)> {
        let channel = mpsc::unbounded_channel();
        self.0
            .send(AppEvent::ClientGetWithMembers(
                *chunk_hash,
                members,
                channel.0,
            ))
            .unwrap();
        channel.1
    }
}

impl App {
    pub fn new(base: BaseHandle, keypair: Keypair, addr: Multiaddr, config: AppConfig) -> Self {
        Self {
            base,
            control: mpsc::unbounded_channel(),
            chunks: Default::default(),
            invite_resource: Arc::new(Semaphore::new(100)),
            client_chunks: Default::default(),
            client_queue: Default::default(),
            put_chunks: None,
            get_chunks: Default::default(),
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
                        // return ControlFlow::Break(());
                        // we are breaking but not waiting for the result, i.e. drop(s) instead of s.await
                        // the better way is to do s.await somewhere appropriate, maybe later TODO
                    }
                }
                other_event => {
                    *event = Some(other_event);
                }
            }
            ControlFlow::<()>::Continue(())
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
                    Gossip(message) => {
                        self.base.response_ok(channel);
                        self.handle_gossip(&message)
                    }
                    Invite(message) => {
                        self.base.response_ok(channel);
                        self.handle_invite(&message);
                    }
                    QueryFragment(message) => self.handle_query_fragment(&message, channel),
                    QueryProof(message) => self.handle_query_proof(&message, channel),
                },
                AppEvent::Rpc(libp2p::request_response::Event::Message {
                    message: Message::Response { response, .. },
                    ..
                }) => match response.inner.unwrap() {
                    QueryFragmentOk(message) => self.handle_query_fragment_ok(&message),
                    QueryProofOk(message) => self.handle_query_proof_ok(&message),
                    Ok(proto::Ok {}) => {}
                },
                AppEvent::Rpc(libp2p::request_response::Event::OutboundFailure {
                    error, ..
                }) if !matches!(error, OutboundFailure::DialFailure) => {
                    tracing::warn!("outbound failure {error:?}")
                }
                AppEvent::Rpc(libp2p::request_response::Event::InboundFailure {
                    error, ..
                }) => {
                    tracing::warn!("inbound failure {error:?}")
                }
                AppEvent::Rpc(_) => {} // do anything?

                AppEvent::ClientInvite(chunk_hash) => self.client_invite(&chunk_hash),
                AppEvent::ClientPut(data, channel) => {
                    assert!(self.put_chunks.is_none());
                    self.put_chunks = Some(channel);
                    self.put(data).await;
                }
                AppEvent::ClientGetWithMembers(chunk_hash, members, channel) => {
                    self.get_chunks.insert(chunk_hash, channel);
                    self.get_with_members(&chunk_hash, members)
                }
            }
        }

        tracing::debug!(peer_id = %PeerId::from_public_key(&self.keypair.public()), "close");
    }

    fn set_timer(&self, duration: Duration, event: AppEvent) {
        let control = self.control.0.clone();
        spawn(async move {
            sleep(duration).await;
            let _ = control.send(event); // could fail if outlive event loop
        });
    }

    async fn put(&mut self, data: Vec<u8>) {
        assert!(self.client_chunks.is_empty());
        assert_eq!(
            data.len(),
            self.config.fragment_size * self.config.fragment_k * self.config.chunk_k
        );
        let encode_span = tracing::info_span!("encode");
        let outer_encoder = encode_span.in_scope(|| {
            Arc::new(WirehairEncoder::new(
                data,
                (self.config.fragment_size * self.config.fragment_k) as _,
            ))
        });
        let mut tasks = Vec::new();
        for _ in 0..self.config.chunk_n {
            let fragment_size = self.config.fragment_size;
            let fragment_k = self.config.fragment_k;
            let outer_encoder = outer_encoder.clone();
            let task = spawn_blocking(move || {
                let mut buffer = vec![0; fragment_size * fragment_k];
                let chunk_index = random();
                outer_encoder.encode(chunk_index, &mut buffer).unwrap();
                let chunk_hash = Code::Sha2_256.digest(&buffer);
                let chunk = ClientChunk {
                    chunk_index,
                    encoder: WirehairEncoder::new(buffer, fragment_size as _),
                    enter_time_sec: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                    index: 0,
                    members: Default::default(),
                    indexes: Default::default(),
                };
                (chunk_hash, chunk)
            });
            tasks.push(task);
        }
        for task in tasks {
            let (chunk_hash, chunk) = task.instrument(encode_span.clone()).await.unwrap();
            self.client_chunks.insert(chunk_hash, chunk);
            if self.client_queue.len() < 3 {
                self.client_invite(&chunk_hash);
            }
            self.client_queue.push_back(chunk_hash);
        }
    }

    fn client_invite(&mut self, chunk_hash: &Multihash) {
        let Some(chunk) = self.client_chunks.get_mut(chunk_hash) else {
            return;
        };
        assert!(chunk.indexes.len() < self.config.fragment_n);

        let prev_index = chunk.index;
        // add some backup invitations to make sure success in the first try
        chunk.index += (((self.config.fragment_n - chunk.indexes.len()) as f32) * 1.2) as u32;
        // chunk.index += (self.config.fragment_n - chunk.indexes.len()) as u32;
        // doing eval in a good network so skip retry old indexes
        tracing::debug!(index = ?(prev_index..chunk.index), "invite chunk {chunk_hash:02x?}");
        for index in prev_index..chunk.index {
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
            spawn(Self::invite_fragment_task(
                Self::fragment_hash(chunk_hash, index),
                self.base.clone(),
                self.invite_resource.clone(),
                self.config.invite_count,
                request,
                PeerId::from_public_key(&self.keypair.public()),
            ));
        }

        self.set_timer(
            self.config.invite_interval,
            AppEvent::ClientInvite(*chunk_hash),
        );
    }

    fn client_handle_query_fragment(
        &mut self,
        message: &proto::QueryFragment,
        channel: ResponseChannel<proto::Response>,
    ) {
        let chunk_hash = message.chunk_hash();
        let member = message.member.as_ref().unwrap();
        let public_key = member.public_key().unwrap();
        if !self.client_verify(&chunk_hash, member.index, &public_key, &member.proof) {
            tracing::warn!(
                "fail to verify chunk {chunk_hash:02x?} index {}",
                member.index
            );
            return;
        }

        let chunk = self.client_chunks.get_mut(&chunk_hash).unwrap();
        let member_id = PeerId::from_public_key(&public_key);
        // check duplicated index / member
        // a little bit duplicated with the last part of this file but i don't care any more
        if chunk.members.contains_key(&member_id) {
            tracing::debug!(id = %member_id, "same member multiple indexes");
            self.base.response_ok(channel);
            return;
        }
        if let Some(prev_key) = chunk.indexes.get(&member.index) {
            tracing::debug!(index = member.index, "same index multiple members");
            let d = |peer_id: &PeerId| {
                kbucket::Key::from(peer_id.to_bytes()).distance(&kbucket::Key::from(chunk_hash))
            };
            let prev_id = PeerId::from_public_key(prev_key);
            if d(&prev_id) <= d(&member_id) {
                self.base.response_ok(channel);
                return;
            }
            let (_, prev_channel) = chunk.members.remove(&prev_id).unwrap();
            self.base.response_ok(prev_channel);
        }
        chunk.indexes.insert(member.index, public_key);
        tracing::debug!(id = %member_id, "insert member chunk {chunk_hash:02x?} index {} group size {}", member.index, chunk.indexes.len());
        chunk
            .members
            .insert(member_id, (Member::new(member, false), channel));

        if chunk.indexes.len() >= self.config.fragment_n {
            tracing::debug!("finalize put chunk {chunk_hash:02x?}");
            let mut chunk = self.client_chunks.remove(&chunk_hash).unwrap();
            let members = Vec::from_iter(chunk.members.values_mut().map(|(member, _)| {
                proto::Member::new(
                    member.index,
                    &chunk.indexes[&member.index],
                    &member.addr,
                    take(&mut member.proof), // not used any more
                )
            }));
            let encoder = Arc::new(chunk.encoder);
            let reply_members = chunk
                .members
                .iter()
                .map(|(id, (member, _))| (*id, member.clone()))
                .collect();
            for (member, channel) in chunk.members.into_values() {
                let encoder = encoder.clone();
                let base = self.base.clone();
                let fragment_size = self.config.fragment_size;
                let members = members.clone();
                if !channel.is_open() {
                    tracing::warn!(index = member.index, "skip closed response channel");
                    continue;
                }
                spawn(async move {
                    let mut fragment = vec![0; fragment_size];
                    encoder.encode(member.index, &mut fragment).unwrap();
                    let response = proto::Response::from(proto::QueryFragmentOk {
                        chunk_hash: chunk_hash.to_bytes(),
                        member: None,
                        fragment,
                        init_members: members.clone(),
                    });
                    base.ingress(move |swarm| {
                        swarm
                            .behaviour_mut()
                            .rpc
                            .send_response(channel, response)
                            .unwrap();
                    });
                });
            }

            self.put_chunks
                .as_ref()
                .unwrap()
                .send((chunk.chunk_index, chunk_hash, reply_members))
                .unwrap();
            if self.client_chunks.is_empty() {
                self.put_chunks = None;
            }

            while !self
                .client_chunks
                .contains_key(self.client_queue.front().as_ref().unwrap())
            {
                self.client_queue.pop_front().unwrap();
                if self.client_queue.is_empty() {
                    break;
                }
                if let Some(&chunk_hash) = self.client_queue.get(2) {
                    self.client_invite(&chunk_hash);
                }
            }
        }
    }

    fn get_with_members(&mut self, chunk_hash: &Multihash, members: HashMap<PeerId, Member>) {
        let request = proto::Request::from(proto::QueryFragment {
            chunk_hash: chunk_hash.to_bytes(),
            member: None,
        });
        for (id, member) in members {
            let addr = member.addr;
            let request = request.clone();
            self.base.ingress(move |swarm| {
                swarm.behaviour_mut().rpc_ensure_address(&id, addr);
                swarm.behaviour_mut().rpc.send_request(&id, request);
            });
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
        chunk.retain_unique(&self.config, true);
        if !chunk
            .members
            .contains_key(&PeerId::from_public_key(&self.keypair.public()))
        {
            tracing::debug!("exit chunk {chunk_hash:02x?}");
            self.chunks.remove(chunk_hash);
            return;
        }
        tracing::debug!(
            "check membership chunk {chunk_hash:02x?} group size {}",
            chunk.fragment_count()
        );

        // assert!(chunk.fragment_count() >= self.config.fragment_k);
        if chunk.fragment_count() < self.config.fragment_k {
            tracing::warn!("exit non-recoverable group chunk {chunk_hash:02x?}");
            self.chunks.remove(chunk_hash);
            return;
        }

        self.invite(chunk_hash);
        self.set_timer(
            self.config.membership_interval,
            AppEvent::Membership(*chunk_hash),
        );
    }

    fn invite(&mut self, chunk_hash: &Multihash) {
        let Some(chunk) = self.chunks.get_mut(chunk_hash) else {
            // 
            return;
        };
        // can it get larger then n?
        if chunk.fragment_count() >= self.config.fragment_n {
            tracing::debug!("finish invite for healthy chunk {chunk_hash:02x?}");
            return;
        }

        // assume no more node below high watermark is avaiable i.e. can be successfully invited any more
        chunk.high_watermark += (self.config.fragment_n - chunk.fragment_count()) as u32;
        let invite_indexes = Vec::from_iter(
            // not use `chunk.watermark()` to because that is for passively accepting, while this is actively inviting
            (chunk.low_watermark(&self.config)..=chunk.high_watermark)
                .filter(|index| !chunk.indexes.contains_key(index)),
        );
        tracing::info!("invite chunk {chunk_hash:02x?} indexes {invite_indexes:?}");
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
                chunk.retain_unique(&self.config, false); // shrink high watermark if possible
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
        // tracing::info!("invite chunk {chunk_hash:02x?} index {index}");
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
        spawn(Self::invite_fragment_task(
            Self::fragment_hash(chunk_hash, index),
            self.base.clone(),
            self.invite_resource.clone(),
            self.config.invite_count,
            request,
            PeerId::from_public_key(&self.keypair.public()),
        ));
    }

    async fn invite_fragment_task(
        fragment_hash: Multihash,
        base: BaseHandle,
        invite_resource: Arc<Semaphore>,
        invite_count: usize,
        request: proto::Request,
        local_id: PeerId,
    ) {
        for (peer_id, peer_addr) in {
            let _guard = invite_resource.acquire().await.unwrap();
            base.query(fragment_hash, invite_count)
                .instrument(tracing::debug_span!("query"))
                .await
        } {
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
                tracing::debug!("query returns local id");
                continue;
            }
            let Some(peer_addr) = peer_addr else {
                tracing::debug!("query returns no address");
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
        tracing::debug!(
            "invited chunk {chunk_hash:02x?} index {}",
            message.fragment_index
        );
        if self.chunks.contains_key(&chunk_hash) {
            tracing::debug!("deplicated invitation chunk {chunk_hash:02x?}");
            return; // need merge?
        }

        let Some(proof) = self.prove(&chunk_hash, message.fragment_index) else {
            tracing::debug!("not selected chunk {chunk_hash:02x?} index {}", message.fragment_index);
            return;
        };

        // this does not hold any more since client invite contains client as single member
        // and make it len() == 1 || len() >= k looks so weird
        // assert!(message.members.len() >= self.config.fragment_k);
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
        tracing::debug!(
            "query fragment chunk {chunk_hash:02x?} index {}",
            message.fragment_index
        );
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
            tracing::debug!("query fragment on missing chunk {chunk_hash:02x?}");
            self.base.response_ok(channel);
            return;
        }

        let Some(member) = message.member.as_ref() else {
            // client request
            let chunk = &self.chunks[&chunk_hash];
            let response = proto::Response::from(proto::QueryFragmentOk {
                chunk_hash: message.chunk_hash.clone(),
                fragment: if let Fragment::Complete(fragment) = &chunk.fragment {fragment.clone()} else {
                    self.base.response_ok(channel);
                    return;
                },
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
            return;
        };

        let public_key = member.public_key().unwrap();
        if !self.verify(&chunk_hash, member.index, &public_key, &member.proof) {
            tracing::warn!("query fragment fail to verify proof");
            self.base.response_ok(channel);
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
        let Some(local_member) = chunk.members.get(&PeerId::from_public_key(&self.keypair.public())) else {
            //
            self.base.response_ok(channel);
            return;
        };
        let response = proto::Response::from(proto::QueryFragmentOk {
            chunk_hash: message.chunk_hash.clone(),
            fragment: fragment.clone(),
            member: Some(proto::Member::new(
                chunk.fragment_index,
                &self.keypair.public(),
                &self.addr,
                local_member.proof.clone(),
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
        if let Some(channel) = self.get_chunks.get(&chunk_hash) {
            let member = message.member.as_ref().unwrap();
            let public_key = member.public_key().unwrap();
            if !self.verify(&chunk_hash, member.index, &public_key, &member.proof) {
                tracing::warn!("client fail to verify fragment");
                return;
            }
            let _ = channel.send((member.index, message.fragment.clone()));
            return;
        }
        if !self.chunks.contains_key(&chunk_hash) {
            //
            return;
        };

        let Some(member) = &message.member else {
            // sent from client
            let chunk = self.chunks.get_mut(&chunk_hash).unwrap();
            chunk.fragment = Fragment::Complete(message.fragment.clone());
            chunk.high_watermark = chunk.fragment_index;
            for member in &message.init_members {
                // unconditional follow client's info
                chunk.indexes.insert(member.index, member.public_key().unwrap());
                chunk.members.insert(PeerId::from_public_key(&member.public_key().unwrap()), Member::new(member, true));
                chunk.high_watermark = u32::max(chunk.high_watermark, member.index);
            }
            self.set_timer(thread_rng().gen_range(Duration::ZERO..self.config.gossip_interval), AppEvent::Gossip(chunk_hash));
            self.set_timer(thread_rng().gen_range(Duration::ZERO..self.config.membership_interval), AppEvent::Membership(chunk_hash));
            return;
        };

        let public_key = member.public_key().unwrap();
        if !self.verify(&chunk_hash, member.index, &public_key, &member.proof) {
            tracing::warn!("query fragment ok fail to verify proof");
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
            tracing::debug!("get fragment after recovering complete");
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
        tracing::info!(
            "recover complete chunk {chunk_hash:02x?} index {}",
            chunk.fragment_index
        );

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
            self.base.response_ok(channel);
            return;
        };
        let local_key = self.keypair.public();
        let Some(local_member) = chunk.members.get(&PeerId::from_public_key(&local_key)) else {
            self.base.response_ok(channel);
            return;
        };
        let response = proto::Response::from(proto::QueryProofOk {
            chunk_hash: message.chunk_hash.clone(),
            member: Some(proto::Member::new(
                chunk.fragment_index,
                &local_key,
                &self.addr,
                local_member.proof.clone(),
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
        chunk.retain_unique(&self.config, false); // shrink high watermark if possible
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
        f64::min(distance.ilog2().unwrap_or(1) as _, 1.)
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
        // we have further watermark check on `insert` so no need to check here
        // hack for client get chunk
        // (if let Some(chunk) = self.chunks.get(chunk_hash) {
        //     chunk.watermark(&self.config).contains(&index)
        // } else {
        //     true
        // }) &&
        public_key.verify(&input, proof)
            && Self::accepted(
                chunk_hash,
                index,
                &PeerId::from_public_key(public_key),
                proof,
            )
    }

    fn client_verify(
        &self,
        chunk_hash: &Multihash,
        index: u32,
        public_key: &PublicKey,
        proof: &[u8],
    ) -> bool {
        let mut input = chunk_hash.to_bytes();
        input.extend(&index.to_be_bytes());
        index < self.client_chunks[chunk_hash].index
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

    fn watermark(&self, config: &AppConfig) -> Range<u32> {
        // loosing high watermark a little bit, because some other member may invite the new member earlier
        // and local member will eventually do so
        // prevent some unnecessary ignore + query proof
        self.low_watermark(config)
            ..u32::max(
                (self.high_watermark as f32 * 1.2) as _,
                self.high_watermark + 10,
            )
    }

    fn fragment_count(&self) -> usize {
        self.indexes.len()
    }

    fn retain_unique(&mut self, config: &AppConfig, check_alive: bool) {
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
            let Some(mut member) = members.remove(&peer_id) else {
                continue;
            };
            if check_alive {
                if !member.alive {
                    tracing::info!("evict not alive member index {}", member.index);
                    continue;
                }
                // skip local member
                if member.index != self.fragment_index {
                    member.alive = false;
                }
            }
            self.indexes.insert(index, public_key.clone());
            self.members.insert(peer_id, member);
            alive_count += 1;

            // all higher indexes are released, shrinking the high watermark
            // loose the guard a little bit because some members may die soon
            if alive_count == config.fragment_n + 10 {
                tracing::debug!("shrink high watermark to {index}");
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
            tracing::debug!(
                "reject inserting chunk {chunk_hash:02x?} index {}",
                member.index
            );
            return false;
        }
        let index = member.index;
        tracing::debug!("insert chunk {chunk_hash:02x?} index {index}");
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
