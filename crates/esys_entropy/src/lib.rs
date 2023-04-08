mod behavior;

use std::{collections::HashMap, future::Future, mem::take, ops::ControlFlow};

use behavior::proto;
use esys_wirehair::WirehairDecoder;
use libp2p::{
    core::{muxing::StreamMuxerBox, transport, ConnectedPoint},
    futures::StreamExt,
    identify::{self, Info},
    identity::Keypair,
    kad::{
        kbucket, record::Key, store::MemoryStore, GetRecordOk, Kademlia, KademliaEvent,
        PutRecordError, QueryResult, Quorum, Record,
    },
    multiaddr,
    multihash::{Code, Hasher, Multihash, MultihashDigest, Sha2_256},
    request_response::ProtocolSupport,
    swarm::{
        AddressScore, NetworkBehaviour as NetworkBehavior, SwarmBuilder, SwarmEvent,
        THandlerErr as HandlerErr,
    },
    Multiaddr, PeerId, Swarm,
};
use rand::{rngs::StdRng, Rng, SeedableRng};
use tokio::{
    select, spawn,
    sync::{mpsc, oneshot, Mutex},
    task::JoinHandle,
};

#[derive(NetworkBehavior)]
pub struct App {
    identify: identify::Behaviour,
    kad: Kademlia<MemoryStore>,
    entropy: behavior::Behavior,
}

pub struct AppControl {
    ingress: mpsc::UnboundedSender<IngressTask>,
    state: ControlState,
}

type IngressTask =
    Box<dyn FnOnce(&mut Swarm<App>, &mut Vec<(AppObserver, oneshot::Sender<()>)>) + Send>;
pub type AppObserver = Box<dyn FnMut(&ControlEvent, &mut Swarm<App>) -> ControlFlow<()> + Send>;
pub type ControlEvent = SwarmEvent<AppEvent, HandlerErr<App>>;

impl App {
    pub fn run(
        name: impl ToString,
        transport: transport::Boxed<(PeerId, StreamMuxerBox)>,
        keypair: Keypair,
    ) -> (JoinHandle<Swarm<Self>>, AppControl) {
        let id = PeerId::from_public_key(&keypair.public());
        let app = Self {
            identify: identify::Behaviour::new(identify::Config::new(
                "/entropy/0.1.0".into(),
                keypair.public(),
            )),
            kad: Kademlia::new(id, MemoryStore::new(id)),
            entropy: behavior::Behavior::new(
                Default::default(),
                [(behavior::Protocol, ProtocolSupport::Full)],
                Default::default(),
            ),
        };
        let mut swarm = SwarmBuilder::with_tokio_executor(transport, app, id).build();
        let mut ingress = mpsc::unbounded_channel();
        let control = AppControl {
            ingress: ingress.0,
            state: ControlState::new(id, keypair),
        };
        let name = name.to_string();
        let handle = spawn(async move {
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
                    event = swarm.next() => {
                        let event = event.unwrap();
                        tracing::trace!(name, ?event);
                        let mut notifies = Vec::new();
                        for (mut observer, notify) in take(&mut observers) {
                            match observer(&event, &mut swarm) {
                                ControlFlow::Continue(()) => observers.push((observer, notify)),
                                ControlFlow::Break(()) => notifies.push(notify),
                            }
                        }
                        for notify in notifies {
                            notify.send(()).unwrap();
                        }
                    }
                }
            }
        });
        (handle, control)
    }
}

impl AppControl {
    pub fn ingress(&self, action: impl FnOnce(&mut Swarm<App>) + Send + Sync + 'static) {
        self.ingress
            .send(Box::new(|swarm, _| action(swarm)))
            .map_err(|_| ())
            .expect("app handler outlives control")
    }

    pub fn subscribe(
        &self,
        observer: impl FnMut(&ControlEvent, &mut Swarm<App>) -> ControlFlow<()> + Send + 'static,
    ) -> impl Future<Output = ()> + Send + 'static {
        let exited = oneshot::channel();
        self.ingress
            .send(Box::new(|_, observers| {
                observers.push((Box::new(observer), exited.0))
            }))
            .map_err(|_| ())
            .expect("app handler outlives control");
        async move { exited.1.await.unwrap() }
    }

    pub fn listen_on(&self, addr: Multiaddr) {
        self.ingress(move |swarm| {
            swarm.listen_on(addr).unwrap();
        });
    }

    pub fn serve_listen(
        &self,
        mut into_external: impl FnMut(&Multiaddr) -> Option<Multiaddr> + Send + 'static,
    ) {
        let s = self.subscribe(move |event, swarm| {
            if let SwarmEvent::NewListenAddr { address, .. } = event {
                if let Some(address) = into_external(address) {
                    tracing::info!(%address, "add external");
                    swarm.add_external_address(address, AddressScore::Infinite);
                }
            }
            ControlFlow::Continue(())
        });
        drop(s);
    }

    pub fn serve_kad(&self) {
        let s = self.subscribe(|event, swarm| {
            if let SwarmEvent::Behaviour(AppEvent::Identify(identify::Event::Received {
                peer_id,
                info,
            })) = event
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
            ControlFlow::Continue(())
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
        self.subscribe(move |event, _| match event {
            SwarmEvent::ConnectionEstablished {
                peer_id,
                endpoint: ConnectedPoint::Dialer { address, .. },
                ..
            } if *address == service => {
                service_id = Some(*peer_id);
                ControlFlow::Continue(())
            }
            SwarmEvent::Behaviour(AppEvent::Identify(identify::Event::Received {
                peer_id,
                ..
            })) if Some(*peer_id) == service_id => ControlFlow::Break(()),
            _ => ControlFlow::Continue(()),
        })
        .await;

        // step 3, kademlia boostrap
        self.ingress(move |swarm| {
            swarm.behaviour_mut().kad.bootstrap().unwrap();
        });
        self.subscribe(move |event, _| {
            if let SwarmEvent::Behaviour(AppEvent::Kad(KademliaEvent::OutboundQueryProgressed {
                result: QueryResult::Bootstrap(result),
                step,
                ..
            })) = event
            {
                assert!(result.is_ok());
                if step.last {
                    return ControlFlow::Break(());
                }
            }
            ControlFlow::Continue(())
        })
        .await;

        // disabled for now, because when `remove_peer` the connection is closed and service peer cannot provide local
        // peer's information for further bootstraping
        // the system should be designed in a way so that boostrap peer can proceed as a normal peer for all time. if
        // it cannot, then we still need to workaround to readd this step, or make some more rendezvour mechanism

        // step 4, remove bootstrap peer to avoid contacting it during query
        // let remove_done = oneshot::channel();
        // self.ingress(move |swarm| {
        //     swarm.behaviour_mut().kad.remove_peer(&service_id.unwrap());
        //     remove_done.0.send(()).unwrap();
        // });
        // remove_done.1.await.unwrap()
    }

    pub async fn register(&self) {
        let put_id = oneshot::channel();
        self.ingress(move |swarm| {
            let addr = &swarm.external_addresses().next().unwrap().addr;
            tracing::debug!(peer_id = %swarm.local_peer_id(), %addr, "register");
            let record = Record::new(swarm.local_peer_id().to_bytes(), addr.to_vec());
            put_id
                .0
                .send(
                    swarm
                        .behaviour_mut()
                        .kad
                        .put_record(record, Quorum::All)
                        .unwrap(),
                )
                .unwrap();
        });
        let put_id = put_id.1.await.unwrap();
        self.subscribe(move |event, _| match event {
            SwarmEvent::Behaviour(AppEvent::Kad(KademliaEvent::OutboundQueryProgressed {
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
                ControlFlow::Break(())
            }
            _ => ControlFlow::Continue(()),
        })
        .await
    }

    // given a key (e.g. hash of encoded fragment), find closest peer's id and address
    pub async fn query(&self, key: Multihash) -> Option<(PeerId, Multiaddr)> {
        let find_id = oneshot::channel();
        self.ingress(move |swarm| {
            find_id
                .0
                .send(swarm.behaviour_mut().kad.get_closest_peers(key))
                .unwrap()
        });
        let find_id = find_id.1.await.unwrap();
        let mut get_id = None;
        let mut peer = oneshot::channel();
        self.subscribe({
            let mut peer = Some(peer.0);
            move |event, swarm| match event {
                SwarmEvent::Behaviour(AppEvent::Kad(KademliaEvent::OutboundQueryProgressed {
                    id,
                    result: QueryResult::GetClosestPeers(result),
                    ..
                })) if *id == find_id => {
                    let Ok(result) = result else {
                        peer.take().unwrap().send(None).unwrap();
                        return ControlFlow::Break(());
                    };
                    // kad excludes local peer id from `GetClosestPeers` result for unknown reason
                    // so by default, the result from closest peer itself is different from the result from other peers
                    // add this workaround to restore a consistent result
                    let mut closest_id = result.peers[0];
                    if kbucket::Key::from(closest_id).distance(&kbucket::Key::from(key))
                        > kbucket::Key::from(*swarm.local_peer_id())
                            .distance(&kbucket::Key::from(key))
                    {
                        closest_id = *swarm.local_peer_id();
                    }

                    get_id = Some(
                        swarm
                            .behaviour_mut()
                            .kad
                            .get_record(Key::new(&closest_id.to_bytes())),
                    );
                    ControlFlow::Continue(())
                }
                SwarmEvent::Behaviour(AppEvent::Kad(KademliaEvent::OutboundQueryProgressed {
                    id,
                    result: QueryResult::GetRecord(result),
                    step,
                    ..
                })) if Some(*id) == get_id => {
                    let result = if let Ok(GetRecordOk::FoundRecord(result)) = result {
                        if !step.last {
                            swarm.behaviour_mut().kad.query_mut(id).unwrap().finish();
                        }
                        Some((
                            PeerId::from_bytes(&result.record.key.to_vec()).unwrap(),
                            Multiaddr::try_from(result.record.value.clone()).unwrap(),
                        ))
                    } else if step.last {
                        None
                    } else {
                        return ControlFlow::Continue(());
                    };
                    peer.take().unwrap().send(result).unwrap();
                    ControlFlow::Break(())
                }
                _ => ControlFlow::Continue(()),
            }
        })
        .await;
        peer.1.try_recv().unwrap()
    }
}

fn is_global(addr: &Multiaddr) -> bool {
    match addr.iter().next() {
        Some(multiaddr::Protocol::Memory(_)) => true,
        Some(multiaddr::Protocol::Ip4(addr)) => !addr.is_private() && !addr.is_loopback(),
        _ => false,
    }
}

#[derive(Debug)]
struct ControlState {
    chunks: HashMap<Multihash, Chunk>,
    peers: HashMap<PeerId, Info>,
    id: PeerId,
    keypair: Keypair,
}

impl ControlState {
    pub fn new(id: PeerId, keypair: Keypair) -> Self {
        Self {
            chunks: Default::default(),
            peers: Default::default(),
            id,
            keypair,
        }
    }
}

#[derive(Debug)]
struct Chunk {
    fragment_index: u32,
    fragment: Fragment,
    members: HashMap<PeerId, u32>,
    proofs: HashMap<u32, (PeerId, Vec<u8>)>,
}

#[derive(Debug)]
enum Fragment {
    Incomplete(Mutex<WirehairDecoder>),
    Complete(Vec<u8>),
}

impl AppControl {
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

    pub fn gossip(&self, chunk_hash: Multihash) {
        let members = &self.state.chunks[&chunk_hash].members;
        let request = proto::Request {
            inner: Some(proto::request::Inner::Gossip(proto::Gossip {
                chunk_hash: chunk_hash.to_bytes(),
                members: members.keys().map(PeerId::to_bytes).collect(),
            })),
        };
        for &peer in members.keys() {
            let request = request.clone();
            self.ingress(move |swarm| {
                swarm.behaviour_mut().entropy.send_request(&peer, request);
            });
        }
    }

    pub async fn invite(&self, chunk_hash: Multihash, index: u32) {
        let chunk = &self.state.chunks[&chunk_hash];
        // TODO check watermarks
        if chunk.proofs.contains_key(&index) {
            return;
        }
        let fragment_hash = Self::fragment_hash(chunk_hash, index);
        // TODO try invite multiple peers
        let (peer_id, peer_addr) = self
            .query(fragment_hash)
            .await
            .expect("found peer to invite");
        if chunk.members.contains_key(&peer_id) {
            return;
        }
        let request = proto::Request {
            inner: Some(proto::request::Inner::Invite(proto::Invite {
                chunk_hash: chunk_hash.to_bytes(),
                fragment_index: index,
                members: chunk.members.keys().map(PeerId::to_bytes).collect(),
            })),
        };
        self.ingress(move |swarm| {
            swarm
                .behaviour_mut()
                .entropy
                .add_address(&peer_id, peer_addr);
            swarm
                .behaviour_mut()
                .entropy
                .send_request(&peer_id, request);
        });
    }

    pub async fn handle_invite(&self, message: proto::Invite) {
        let chunk_hash = Multihash::from_bytes(&message.chunk_hash).unwrap();
        if self.state.chunks.contains_key(&chunk_hash) {
            return; //
        }
        let Some(proof) = self.prove(chunk_hash, message.fragment_index) else {
            //
            return;
        };
        let mut chunk = Chunk {
            fragment_index: message.fragment_index,
            fragment: Fragment::Incomplete(Mutex::new(WirehairDecoder::new(0, 0))), //
            members: Default::default(),
            proofs: Default::default(),
        };
        chunk.members.insert(self.state.id, message.fragment_index);
        chunk
            .proofs
            .insert(message.fragment_index, (self.state.id, proof.clone()));
        // TODO
    }

    pub fn handle_query_fragment(
        &self,
        peer_id: PeerId,
        message: proto::QueryFragment,
    ) -> Option<proto::QueryFragmentOk> {
        let chunk_hash = Multihash::from_bytes(&message.chunk_hash).unwrap();
        let Some(chunk) = self.state.chunks.get(&chunk_hash) else {
            //
            return None;
        };

        if !self.verify(chunk_hash, message.fragment_index, peer_id, &message.proof) {
            //
            return None;
        }

        let Fragment::Complete(fragment) = &chunk.fragment else {
            panic!("receive query fragment before sending gossip")
        };
        let response = proto::QueryFragmentOk {
            chunk_hash: message.chunk_hash,
            fragment_index: chunk.fragment_index,
            fragment: fragment.clone(),
        };
        Some(response)
    }

    // TODO homomorphic hashing
    fn fragment_hash(chunk_hash: Multihash, index: u32) -> Multihash {
        let mut input = chunk_hash.to_bytes();
        input.extend(&index.to_be_bytes());
        Code::Sha2_256.digest(&input)
    }

    fn accept_probablity(chunk_hash: Multihash, index: u32, peer_id: PeerId) -> f64 {
        let fragment_hash = Self::fragment_hash(chunk_hash, index);
        let distance = kbucket::Key::from(fragment_hash).distance(&kbucket::Key::from(peer_id));
        // TODO tune the probability distribution properly
        match distance.ilog2() {
            None => 0.95,
            Some(i) if i <= 18 => 0.9 - 0.05 * i as f64,
            _ => 0.,
        }
    }

    fn accepted(chunk_hash: Multihash, index: u32, peer_id: PeerId, proof: &[u8]) -> bool {
        let seed = {
            let mut hasher = Sha2_256::default();
            hasher.update(proof);
            hasher.finalize().try_into().unwrap()
        };
        StdRng::from_seed(seed).gen_bool(Self::accept_probablity(chunk_hash, index, peer_id))
    }

    fn prove(&self, chunk_hash: Multihash, index: u32) -> Option<Vec<u8>> {
        let proof = {
            let mut input = chunk_hash.to_bytes();
            input.extend(&index.to_be_bytes());
            self.state.keypair.sign(&input).unwrap()
        };
        if Self::accepted(chunk_hash, index, self.state.id, &proof) {
            Some(proof)
        } else {
            None
        }
    }

    fn verify(&self, chunk_hash: Multihash, index: u32, peer_id: PeerId, proof: &[u8]) -> bool {
        let mut input = chunk_hash.to_bytes();
        input.extend(&index.to_be_bytes());
        self.state.peers[&peer_id].public_key.verify(&input, proof)
            && Self::accepted(chunk_hash, index, peer_id, proof)
    }
}
