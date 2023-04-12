mod behavior;

use std::{
    collections::{BTreeMap, HashMap},
    future::Future,
    mem::{replace, take},
    ops::{ControlFlow, RangeInclusive},
    sync::Mutex,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use behavior::proto;
use esys_wirehair::WirehairDecoder;
use libp2p::{
    core::{muxing::StreamMuxerBox, transport, ConnectedPoint},
    futures::StreamExt,
    identify::{self, Behaviour as Identify},
    identity::{Keypair, PublicKey},
    kad::{
        kbucket, record::Key, store::MemoryStore, GetRecordError, GetRecordOk, Kademlia,
        KademliaEvent, PutRecordError, QueryResult, Quorum, Record,
    },
    multiaddr,
    multihash::{Code, Hasher, Multihash, MultihashDigest, Sha2_256},
    request_response::{Message, ProtocolSupport, ResponseChannel},
    swarm::{
        AddressScore, NetworkBehaviour as NetworkBehavior, SwarmBuilder,
        SwarmEvent::{self, Behaviour as Behavior},
        THandlerErr as HandlerErr,
    },
    Multiaddr, PeerId, Swarm,
};
use rand::{rngs::StdRng, thread_rng, Rng, SeedableRng};
use tokio::{
    select, spawn,
    sync::{mpsc, oneshot},
    task::JoinHandle,
    time::sleep,
};
use tracing::{
    debug_span,
    field::{display, Empty},
    Instrument,
};

#[derive(NetworkBehavior)]
pub struct Base {
    identify: Identify,
    kad: Kademlia<MemoryStore>,
    rpc: behavior::Behavior,
}

impl Base {
    fn rpc_ensure_address(&mut self, peer_id: &PeerId, addr: Multiaddr) {
        // silly way to prevent repeated address for a peer to cause problems
        self.rpc.remove_address(peer_id, &addr);
        self.rpc.add_address(peer_id, addr);
    }
}

#[derive(Clone)]
pub struct BaseHandle {
    ingress: mpsc::UnboundedSender<IngressTask>,
}

type IngressTask = Box<dyn FnOnce(&mut Swarm<Base>, &mut Vec<AppObserver>) + Send>;
pub type AppObserver =
    Box<dyn FnMut(&mut Option<ObserverEvent>, &mut Swarm<Base>) -> ControlFlow<()> + Send>;
pub type ObserverEvent = SwarmEvent<BaseEvent, HandlerErr<Base>>;

impl Base {
    pub fn run(
        name: impl ToString,
        transport: transport::Boxed<(PeerId, StreamMuxerBox)>,
        keypair: &Keypair,
    ) -> (JoinHandle<Swarm<Self>>, BaseHandle) {
        let id = PeerId::from_public_key(&keypair.public());
        let app = Self {
            identify: Identify::new(identify::Config::new(
                "/entropy/0.1.0".into(),
                keypair.public(),
            )),
            kad: Kademlia::new(id, MemoryStore::new(id)),
            rpc: behavior::Behavior::new(
                Default::default(),
                [(behavior::Protocol, ProtocolSupport::Full)],
                Default::default(),
            ),
        };
        let mut swarm = SwarmBuilder::with_tokio_executor(transport, app, id).build();
        let mut ingress = mpsc::unbounded_channel();
        let handle = BaseHandle { ingress: ingress.0 };
        let name = name.to_string();
        let event_loop = spawn(async move {
            tracing::trace!("launch app event looop");
            let mut observers = Vec::new();
            loop {
                select! {
                    action = ingress.1.recv() => {
                        let Some(action) = action else {
                            tracing::trace!("exit app event loop on ingress channel close");
                            return swarm;
                        };
                        action(&mut swarm, &mut observers);
                    }
                    mut event = swarm.next() => {
                        tracing::trace!(name, ?event);
                        for mut observer in take(&mut observers) {
                            if event.is_none() || observer(&mut event, &mut swarm).is_continue() {
                                observers.push(observer);
                            }
                        }
                    }
                }
            }
        });
        (event_loop, handle)
    }
}

impl BaseHandle {
    pub fn ingress(&self, action: impl FnOnce(&mut Swarm<Base>) + Send + Sync + 'static) {
        self.ingress
            .send(Box::new(|swarm, _| action(swarm)))
            .map_err(|_| ())
            .expect("event loop outlives handle")
    }

    pub fn ingress_wait<T: Send + 'static>(
        &self,
        action: impl FnOnce(&mut Swarm<Base>) -> T + Send + Sync + 'static,
    ) -> impl Future<Output = T> + Send + 'static {
        let result = oneshot::channel();
        self.ingress(move |swarm| {
            result
                .0
                .send(action(swarm))
                .map_err(|_| ())
                .expect("ingress waiter wait on result")
        });
        async { result.1.await.expect("event loop outlives handle") }
    }

    pub fn subscribe<T: Send + 'static>(
        &self,
        mut observer: impl FnMut(&mut Option<ObserverEvent>, &mut Swarm<Base>) -> ControlFlow<T>
            + Send
            + 'static,
    ) -> impl Future<Output = T> + Send + 'static {
        let (result_in, result_out) = oneshot::channel();
        let mut result_in = Some(result_in);
        self.ingress
            .send(Box::new(|_, observers| {
                observers.push(Box::new(move |event, swarm| match observer(event, swarm) {
                    ControlFlow::Break(result) => {
                        result_in
                            .take()
                            .unwrap()
                            .send(result)
                            .map_err(|_| ())
                            .expect("subcriber wait on result if ever breaking");
                        ControlFlow::Break(())
                    }
                    ControlFlow::Continue(()) => ControlFlow::Continue(()),
                }))
            }))
            .map_err(|_| ())
            .expect("event loop outlives handle");
        async move { result_out.await.expect("event loop outlives handle") }
    }

    pub fn listen_on(&self, addr: Multiaddr) {
        self.ingress(move |swarm| {
            swarm.listen_on(addr).unwrap();
        });
    }

    pub fn serve_add_external_address(
        &self,
        mut into_external: impl FnMut(&Multiaddr) -> Option<Multiaddr> + Send + 'static,
    ) {
        let s = self.subscribe(move |event, swarm| {
            if let SwarmEvent::NewListenAddr { address, .. } = event.as_ref().unwrap() {
                if let Some(address) = into_external(address) {
                    tracing::info!(peer_id = %swarm.local_peer_id(), %address, "add external");
                    swarm.add_external_address(address, AddressScore::Infinite);
                }
                *event = None;
            }
            ControlFlow::<()>::Continue(())
        });
        drop(s);
    }

    pub fn serve_kad_add_address(&self) {
        let s = self.subscribe(|event, swarm| {
            if let Behavior(BaseEvent::Identify(identify::Event::Received { peer_id, info })) =
                event.as_ref().unwrap()
            {
                swarm.behaviour_mut().kad.add_address(
                    peer_id,
                    info.listen_addrs
                        .iter()
                        .find(|addr| is_global(addr))
                        .unwrap()
                        .to_owned(),
                );
            }
            ControlFlow::<()>::Continue(())
        });
        drop(s);
    }

    pub async fn boostrap(&self, service: Multiaddr) {
        // step 1, dial boostrap service
        self.ingress({
            let service = service.clone();
            move |swarm| swarm.dial(service).unwrap()
        });

        // step 2, wait until boostrap service peer id is recorded into kademlia
        let mut service_id = None;
        self.subscribe(move |event, _| match event.as_ref().unwrap() {
            SwarmEvent::ConnectionEstablished {
                peer_id,
                endpoint: ConnectedPoint::Dialer { address, .. },
                ..
            } if *address == service => {
                service_id = Some(*peer_id);
                ControlFlow::Continue(())
            }
            // assert this happens after the one above
            Behavior(BaseEvent::Identify(identify::Event::Received { peer_id, .. }))
                if Some(*peer_id) == service_id =>
            {
                ControlFlow::Break(())
            }
            _ => ControlFlow::Continue(()),
        })
        .await;

        // step 3, kademlia boostrap
        self.ingress(move |swarm| {
            swarm.behaviour_mut().kad.bootstrap().unwrap();
        });
        self.subscribe(move |event, _| {
            if let Behavior(BaseEvent::Kad(KademliaEvent::OutboundQueryProgressed {
                result: QueryResult::Bootstrap(result),
                step,
                ..
            })) = event.as_ref().unwrap()
            {
                assert!(result.is_ok(), "then there's nothing we can do");
                if step.last {
                    return ControlFlow::Break(());
                }
                *event = None;
            }
            ControlFlow::Continue(())
        })
        .await;

        // disabled for now, because when `remove_peer` the connection is closed and service peer will not provide local
        // peer's information for further bootstraping
        // the system should be designed in a way so that boostrap peer can proceed as a normal peer for all time. if
        // it cannot, then we still need to workaround to readd this step, or make some more rendezvour mechanism
        // notice that service peer does not `register`, so it should never participant into RPC and be dedicated for
        // bootstraping for all the time

        // step 4, remove bootstrap peer to avoid contacting it during query
        // let remove_done = oneshot::channel();
        // self.ingress(move |swarm| {
        //     swarm.behaviour_mut().kad.remove_peer(&service_id.unwrap());
        //     remove_done.0.send(()).unwrap();
        // });
        // remove_done.1.await.unwrap()
    }

    pub async fn register(&self) {
        let span = debug_span!("register", peer_id = Empty, addr = Empty);
        let put_id = self
            .ingress_wait({
                let span = span.clone();
                move |swarm| {
                    let addr = &swarm.external_addresses().next().unwrap().addr;
                    span.record("peer_id", display(swarm.local_peer_id()));
                    span.record("addr", display(addr));
                    let record = Record::new(swarm.local_peer_id().to_bytes(), addr.to_vec());
                    swarm
                        .behaviour_mut()
                        .kad
                        .put_record(record, Quorum::All)
                        .unwrap()
                }
            })
            .instrument(span.clone())
            .await;
        self.subscribe(move |event, _| match event.as_ref().unwrap() {
            Behavior(BaseEvent::Kad(KademliaEvent::OutboundQueryProgressed {
                id,
                result: QueryResult::PutRecord(result),
                ..
            })) if *id == put_id => {
                if let Err(err) = result {
                    assert!(matches!(err, PutRecordError::QuorumFailed { .. }));
                    tracing::warn!(
                        "put record quorum failed, should not happen if launched sufficient peers"
                    );
                }
                *event = None;
                ControlFlow::Break(())
            }
            _ => ControlFlow::Continue(()),
        })
        .instrument(span)
        .await
    }

    pub async fn query_address(&self, peer_id: &PeerId) -> Option<Multiaddr> {
        let key = Key::new(&peer_id.to_bytes());
        let get_id = self
            .ingress_wait(move |swarm| swarm.behaviour_mut().kad.get_record(key))
            .await;
        // tracing::debug!(%peer_id, ?get_id);
        self.subscribe(move |event, swarm| match event.take().unwrap() {
            Behavior(BaseEvent::Kad(KademliaEvent::OutboundQueryProgressed {
                id,
                result: QueryResult::GetRecord(result),
                ..
            })) if id == get_id => {
                let result = match result {
                    Ok(GetRecordOk::FoundRecord(result)) => {
                        if let Some(mut query) = swarm.behaviour_mut().kad.query_mut(&id) {
                            query.finish()
                        }
                        Some(Multiaddr::try_from(result.record.value).unwrap())
                    }
                    Err(GetRecordError::NotFound { .. }) => None,
                    _ => unreachable!("either FoundRecord or NotFound should be delivered before"),
                };
                ControlFlow::Break(result)
            }
            other_event => {
                *event = Some(other_event);
                ControlFlow::Continue(())
            }
        })
        .await
    }

    // given a key (e.g. hash of encoded fragment), find closest peers' id and address
    pub async fn query(&self, key: Multihash, n: usize) -> Vec<(PeerId, Option<Multiaddr>)> {
        let find_id = self
            .ingress_wait(move |swarm| swarm.behaviour_mut().kad.get_closest_peers(key))
            .await;
        let peers = self
            .subscribe(move |event, swarm| match event.take().unwrap() {
                Behavior(BaseEvent::Kad(KademliaEvent::OutboundQueryProgressed {
                    id,
                    result: QueryResult::GetClosestPeers(result),
                    ..
                })) if id == find_id => {
                    let Ok(result) = result else {
                        unimplemented!()
                    };
                    // kad excludes local peer id from `GetClosestPeers` result for unknown reason
                    // so by default, the result from closest peers themselves is different from the others
                    // add this workaround to restore a consistent result
                    let mut peers = result.peers;
                    let k = |peer_id: &PeerId| {
                        kbucket::Key::from(*peer_id).distance(&kbucket::Key::from(key))
                    };
                    let local_id = *swarm.local_peer_id();
                    let index = peers.binary_search_by_key(&k(&local_id), k).expect_err(
                        "local peer id is always excluded from get closest peers result",
                    );
                    peers.insert(index, local_id);
                    peers.pop();
                    ControlFlow::Break(peers)
                }
                other_event => {
                    *event = Some(other_event);
                    ControlFlow::Continue(())
                }
            })
            .await;
        // tracing::debug!(?peers);
        let tasks = Vec::from_iter(
            peers
                .into_iter()
                .map(|peer_id| {
                    let control = self.clone();
                    let task = spawn(async move { control.query_address(&peer_id).await });
                    (peer_id, task)
                })
                .take(n),
        );
        let mut peers = Vec::new();
        for (peer_id, task) in tasks {
            peers.push((peer_id, task.await.unwrap()));
        }
        peers
    }
}

fn is_global(addr: &Multiaddr) -> bool {
    match addr.iter().next() {
        Some(multiaddr::Protocol::Memory(_)) => true,
        Some(multiaddr::Protocol::Ip4(addr)) => !addr.is_private() && !addr.is_loopback(),
        _ => false,
    }
}

pub struct App {
    base: BaseHandle,
    control: (
        mpsc::UnboundedSender<AppEvent>,
        mpsc::UnboundedReceiver<AppEvent>,
    ),
    keypair: Keypair,
    addr: Multiaddr,
    chunks: HashMap<Multihash, Chunk>,

    config: AppConfig,
}

pub struct AppConfig {
    pub invite_count: usize,
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

#[derive(Debug)]
enum AppEvent {
    // Close,
    Rpc(<behavior::Behavior as NetworkBehavior>::OutEvent),
    Gossip(Multihash),
    Membership(Multihash),
    Invite(Multihash),
    // client request
}

impl App {
    pub fn new(base: BaseHandle, keypair: Keypair, addr: Multiaddr, config: AppConfig) -> Self {
        Self {
            base,
            control: mpsc::unbounded_channel(),
            chunks: Default::default(),
            addr,
            keypair,
            config,
        }
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
                // ControlEvent::Close => break,
                AppEvent::Gossip(chunk_hash) => self.gossip(&chunk_hash),
                AppEvent::Membership(chunk_hash) => self.check_membership(&chunk_hash).await,
                AppEvent::Invite(chunk_hash) => self.invite(&chunk_hash).await,
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

    async fn check_membership(&mut self, chunk_hash: &Multihash) {
        let chunk = self.chunks.get_mut(chunk_hash).unwrap();
        chunk.retain_alive(&self.config);
        if !chunk
            .members
            .contains_key(&PeerId::from_public_key(&self.keypair.public()))
        {
            self.chunks.remove(chunk_hash);
            return;
        }

        assert!(chunk.fragment_count() >= self.config.fragment_k);
        self.invite(chunk_hash).await;
        self.set_timer(
            self.config.membership_interval,
            AppEvent::Membership(*chunk_hash),
        );
    }

    async fn invite(&mut self, chunk_hash: &Multihash) {
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
            self.invite_index(chunk_hash, index).await;
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

    async fn invite_index(&self, chunk_hash: &Multihash, index: u32) {
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
        for (peer_id, peer_addr) in self
            .base
            .query(
                Self::fragment_hash(chunk_hash, index),
                self.config.invite_count,
            )
            .await
        {
            // if chunk.members.contains_key(&peer_id) {
            //     continue;
            // }
            //
            // skip this check may cause some member to be re-invited (with low probability hopefully)
            // which will be ignored by honest members, and a faulty member may try duplicated join anyway regardless
            // of this inviting (and will be rejected), so it's fine
            //
            // however, should we filter out `joining_memebers` in some way?

            let Some(peer_addr) = peer_addr else {
                continue;
            };
            let request = request.clone();
            self.base.ingress(move |swarm| {
                swarm
                    .behaviour_mut()
                    .rpc_ensure_address(&peer_id, peer_addr);
                swarm.behaviour_mut().rpc.send_request(&peer_id, request);
            });
        }
    }

    fn handle_invite(&mut self, message: &proto::Invite) {
        let chunk_hash = message.chunk_hash();
        if self.chunks.contains_key(&chunk_hash) {
            return; // need merge?
        }

        let Some(proof) = self.prove(&chunk_hash, message.fragment_index) else {
            //
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
        let member = message.member.as_ref().unwrap();
        let chunk_hash = message.chunk_hash();
        if !self.chunks.contains_key(&chunk_hash) {
            //
            return;
        };

        let public_key = member.public_key().unwrap();
        if !self.verify(&chunk_hash, member.index, &public_key, &member.proof) {
            //
            return;
        }
        // unconditionally insert members that are queried previously
        // mostly for simplifying stuff, and should not break anything
        let chunk = self.chunks.get_mut(&chunk_hash).unwrap();
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
        self.set_timer(
            self.config.membership_interval
                + thread_rng().gen_range(Duration::ZERO..self.config.membership_interval),
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
        match distance.ilog2() {
            None => 0.95,
            Some(i) if i <= 18 => 0.9 - 0.05 * i as f64,
            _ => 0.,
        }
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
