mod behavior;

use std::{collections::HashMap, future::Future, mem::replace, ops::ControlFlow};

use behavior::proto;
use esys_wirehair::WirehairDecoder;
use libp2p::{
    core::{muxing::StreamMuxerBox, transport, ConnectedPoint},
    futures::StreamExt,
    identify,
    identity::{Keypair, PublicKey},
    kad::{
        kbucket, record::Key, store::MemoryStore, GetRecordError, GetRecordOk, Kademlia,
        KademliaEvent, PutRecordError, QueryResult, Quorum, Record,
    },
    multiaddr,
    multihash::{Code, Hasher, Multihash, MultihashDigest, Sha2_256},
    request_response::{ProtocolSupport, ResponseChannel},
    swarm::{
        AddressScore, NetworkBehaviour as NetworkBehavior, SwarmBuilder,
        SwarmEvent::{self, Behaviour as Behavior},
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

impl App {
    fn entropy_ensure_address(&mut self, peer_id: &PeerId, addr: Multiaddr) {
        // silly way to prevent repeated address for a peer to cause problems
        self.entropy.remove_address(peer_id, &addr);
        self.entropy.add_address(peer_id, addr);
    }
}

#[derive(Clone)]
pub struct AppHandle {
    ingress: mpsc::UnboundedSender<IngressTask>,
}

type IngressTask = Box<dyn FnOnce(&mut Swarm<App>, &mut Vec<AppObserver>) + Send>;
pub type AppObserver = Box<dyn FnMut(&ControlEvent, &mut Swarm<App>) -> ControlFlow<()> + Send>;
pub type ControlEvent = SwarmEvent<AppEvent, HandlerErr<App>>;

impl App {
    pub fn run(
        name: impl ToString,
        transport: transport::Boxed<(PeerId, StreamMuxerBox)>,
        keypair: Keypair,
    ) -> (JoinHandle<Swarm<Self>>, AppHandle) {
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
        let control = AppHandle { ingress: ingress.0 };
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
                        observers.retain_mut(|observer| matches!(observer(&event, &mut swarm), ControlFlow::Continue(())));
                    }
                }
            }
        });
        (handle, control)
    }
}

impl AppHandle {
    pub fn ingress(&self, action: impl FnOnce(&mut Swarm<App>) + Send + Sync + 'static) {
        self.ingress
            .send(Box::new(|swarm, _| action(swarm)))
            .map_err(|_| ())
            .expect("app handler outlives control")
    }

    pub fn ingress_wait<T: Send + 'static>(
        &self,
        action: impl FnOnce(&mut Swarm<App>) -> T + Send + Sync + 'static,
    ) -> impl Future<Output = T> + Send + 'static {
        let result = oneshot::channel();
        self.ingress(move |swarm| result.0.send(action(swarm)).map_err(|_| ()).unwrap());
        async { result.1.await.unwrap() }
    }

    pub fn subscribe<T: Send + 'static>(
        &self,
        mut observer: impl FnMut(&ControlEvent, &mut Swarm<App>) -> ControlFlow<T> + Send + 'static,
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
                            .expect("app handler outlives control");
                        ControlFlow::Break(())
                    }
                    ControlFlow::Continue(()) => ControlFlow::Continue(()),
                }))
            }))
            .map_err(|_| ())
            .expect("app handler outlives control");
        async move { result_out.await.unwrap() }
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
            if let SwarmEvent::NewListenAddr { address, .. } = event {
                if let Some(address) = into_external(address) {
                    tracing::info!(%address, "add external");
                    swarm.add_external_address(address, AddressScore::Infinite);
                }
            }
            ControlFlow::<()>::Continue(())
        });
        drop(s);
    }

    pub fn serve_kad_add_address(&self) {
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
        let put_id = self
            .ingress_wait(move |swarm| {
                let addr = &swarm.external_addresses().next().unwrap().addr;
                tracing::debug!(peer_id = %swarm.local_peer_id(), %addr, "register");
                let record = Record::new(swarm.local_peer_id().to_bytes(), addr.to_vec());
                swarm
                    .behaviour_mut()
                    .kad
                    .put_record(record, Quorum::All)
                    .unwrap()
            })
            .await;
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

    pub async fn query_address(&self, peer_id: &PeerId) -> Option<Multiaddr> {
        let key = Key::new(&peer_id.to_bytes());
        let get_id = self
            .ingress_wait(move |swarm| swarm.behaviour_mut().kad.get_record(key))
            .await;
        // tracing::debug!(%peer_id, ?get_id);
        self.subscribe(move |event, swarm| match event {
            Behavior(AppEvent::Kad(KademliaEvent::OutboundQueryProgressed {
                id,
                result: QueryResult::GetRecord(result),
                ..
            })) if *id == get_id => {
                let result = match result {
                    Ok(GetRecordOk::FoundRecord(result)) => {
                        if let Some(mut query) = swarm.behaviour_mut().kad.query_mut(id) {
                            query.finish()
                        }
                        Some(Multiaddr::try_from(result.record.value.clone()).unwrap())
                    }
                    Err(GetRecordError::NotFound { .. }) => None,
                    _ => unreachable!("either FoundRecord or NotFound should be delivered before"),
                };
                ControlFlow::Break(result)
            }
            _ => ControlFlow::Continue(()),
        })
        .await
    }

    // given a key (e.g. hash of encoded fragment), find closest peers' id and address
    pub async fn query(&self, key: Multihash, n: usize) -> Vec<(PeerId, Option<Multiaddr>)> {
        let find_id = self
            .ingress_wait(move |swarm| swarm.behaviour_mut().kad.get_closest_peers(key))
            .await;
        let peers = self
            .subscribe(move |event, swarm| match event {
                SwarmEvent::Behaviour(AppEvent::Kad(KademliaEvent::OutboundQueryProgressed {
                    id,
                    result: QueryResult::GetClosestPeers(result),
                    ..
                })) if *id == find_id => {
                    let Ok(result) = result else {
                        unimplemented!()
                    };
                    // kad excludes local peer id from `GetClosestPeers` result for unknown reason
                    // so by default, the result from closest peers themselves is different from the others
                    // add this workaround to restore a consistent result
                    let mut peers = result.peers.clone();
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
                _ => ControlFlow::Continue(()),
            })
            .await;
        tracing::debug!(?peers);
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

pub struct AppControl {
    pub handle: AppHandle,
    keypair: Keypair,
    addr: Multiaddr,
    chunks: HashMap<Multihash, Chunk>,
}

#[derive(Debug)]
struct Chunk {
    fragment_index: u32,
    fragment: Fragment,
    members: HashMap<PublicKey, (u32, Multiaddr)>,
    proofs: HashMap<u32, (PublicKey, Vec<u8>)>,
}

#[derive(Debug)]
enum Fragment {
    Incomplete(Mutex<WirehairDecoder>),
    Complete(Vec<u8>),
}

impl AppControl {
    pub fn new(handle: AppHandle, keypair: Keypair, addr: Multiaddr) -> Self {
        Self {
            handle,
            chunks: Default::default(),
            addr,
            keypair,
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

    pub fn gossip(&self, chunk_hash: Multihash) {
        let chunk = &self.chunks[&chunk_hash];
        let request = proto::Request::from(proto::Gossip {
            chunk_hash: chunk_hash.to_bytes(),
            members: chunk.gossip_members(),
        });
        for (peer_key, (_, peer_addr)) in &chunk.members {
            if peer_key == &self.keypair.public() {
                continue;
            }
            let peer_id = PeerId::from_public_key(peer_key);
            let peer_addr = peer_addr.clone();
            let request = request.clone();
            self.handle.ingress(move |swarm| {
                swarm
                    .behaviour_mut()
                    .entropy_ensure_address(&peer_id, peer_addr);
                swarm
                    .behaviour_mut()
                    .entropy
                    .send_request(&peer_id, request);
            });
        }
    }

    pub fn handle_gossip(&self, message: &proto::Gossip) {
        //
    }

    pub async fn invite(&self, chunk_hash: Multihash, index: u32) {
        let chunk = &self.chunks[&chunk_hash];
        // TODO check watermarks
        assert!(!chunk.proofs.contains_key(&index));
        for (peer_id, peer_addr) in self
            .handle
            .query(Self::fragment_hash(chunk_hash, index), 1) // TODO configure this
            .await
        {
            // if chunk.members.contains_key(&peer_id) {
            //     continue;
            // }
            let Some(peer_addr) = peer_addr else {
                continue;
            };
            let request = proto::Request::from(proto::Invite {
                chunk_hash: chunk_hash.to_bytes(),
                fragment_index: index,
                members: chunk.invite_members(),
            });
            self.handle.ingress(move |swarm| {
                swarm
                    .behaviour_mut()
                    .entropy_ensure_address(&peer_id, peer_addr);
                swarm
                    .behaviour_mut()
                    .entropy
                    .send_request(&peer_id, request);
            });
        }
    }

    pub async fn handle_invite(&mut self, message: &proto::Invite) {
        let chunk_hash = message.chunk_hash();
        if self.chunks.contains_key(&chunk_hash) {
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
        for member in &message.members {
            let public_key = PublicKey::from_protobuf_encoding(&member.public_key).unwrap();
            if !self.verify(chunk_hash, member.index, &public_key, &member.proof) {
                //
                continue;
            }
            // TODO one peer multiple index / multiple peer one index
            chunk.members.insert(
                public_key.clone(),
                (
                    member.index,
                    Multiaddr::try_from(member.addr.clone()).unwrap(),
                ),
            );
            chunk
                .proofs
                .insert(member.index, (public_key, member.proof.clone()));
        }
        // TODO less than k
        if chunk.proofs.len() < 10 {
            //
            return;
        }
        chunk.members.insert(
            self.keypair.public(),
            (message.fragment_index, self.addr.clone()),
        );
        chunk.proofs.insert(
            message.fragment_index,
            (self.keypair.public(), proof.clone()),
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
        for (peer_key, (_, addr)) in &chunk.members {
            let peer_id = PeerId::from_public_key(peer_key);
            let addr = addr.clone();
            let request = request.clone();
            self.handle.ingress(move |swarm| {
                swarm.behaviour_mut().entropy_ensure_address(&peer_id, addr);
                swarm
                    .behaviour_mut()
                    .entropy
                    .send_request(&peer_id, request);
            });
        }

        self.chunks.insert(chunk_hash, chunk);
    }

    pub fn handle_query_fragment(
        &self,
        message: &proto::QueryFragment,
        channel: ResponseChannel<proto::Response>,
    ) {
        let chunk_hash = message.chunk_hash();
        let Some(chunk) = self.chunks.get(&chunk_hash) else {
            //
            return;
        };

        let member = message.member.as_ref().unwrap();
        if !self.verify(
            chunk_hash,
            member.index,
            &member.public_key().unwrap(),
            &member.proof,
        ) {
            //
            return;
        }

        // TODO keep new member's proof somewhere so it can immediately be accepted upon receiving gossip

        let Fragment::Complete(fragment) = &chunk.fragment else {
            panic!("receive query fragment before sending gossip")
        };
        let response = proto::Response::from(proto::QueryFragmentOk {
            chunk_hash: message.chunk_hash.clone(),
            fragment_index: chunk.fragment_index,
            fragment: fragment.clone(),
        });
        self.handle.ingress(move |swarm| {
            swarm
                .behaviour_mut()
                .entropy
                .send_response(channel, response)
                .unwrap();
        });
    }

    pub fn handle_query_fragment_ok(&mut self, message: &proto::QueryFragmentOk) {
        let chunk_hash = message.chunk_hash();
        let Some(chunk) = self.chunks.get_mut(&chunk_hash) else {
            //
            return;
        };
        let Fragment::Incomplete(decoder) = &mut chunk.fragment else {
            //
            return;
        };

        let recovered = decoder
            .get_mut()
            .decode(message.fragment_index, &message.fragment)
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
        let mut fragment = vec![0; 0]; //
        decoder
            .into_inner()
            .into_encoder()
            .unwrap()
            .encode(chunk.fragment_index, &mut fragment)
            .unwrap();
        let _ = replace(&mut chunk.fragment, Fragment::Complete(fragment));

        self.gossip(chunk_hash); // set a timer here?
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
        let response = proto::Response::from(proto::QueryProofOk {
            chunk_hash: message.chunk_hash.clone(),
            member: Some(proto::Member::new(
                chunk.fragment_index,
                &self.keypair.public(),
                &self.addr,
                chunk.proofs[&chunk.fragment_index].1.clone(),
            )),
        });
        self.handle.ingress(move |swarm| {
            swarm
                .behaviour_mut()
                .entropy
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
        if !self.verify(chunk_hash, member.index, &public_key, &member.proof) {
            //
            return;
        }
        let chunk = self.chunks.get_mut(&chunk_hash).unwrap();
        chunk
            .members
            .insert(public_key.clone(), (member.index, member.addr()));
        chunk
            .proofs
            .insert(member.index, (public_key, member.proof.clone()));
        // TODO update high watermark
    }

    // TODO homomorphic hashing
    fn fragment_hash(chunk_hash: Multihash, index: u32) -> Multihash {
        let mut input = chunk_hash.to_bytes();
        input.extend(&index.to_be_bytes());
        Code::Sha2_256.digest(&input)
    }

    fn accept_probablity(chunk_hash: Multihash, index: u32, peer_id: &PeerId) -> f64 {
        let fragment_hash = Self::fragment_hash(chunk_hash, index);
        let distance = kbucket::Key::from(fragment_hash).distance(&kbucket::Key::from(*peer_id));
        // TODO tune the probability distribution properly
        match distance.ilog2() {
            None => 0.95,
            Some(i) if i <= 18 => 0.9 - 0.05 * i as f64,
            _ => 0.,
        }
    }

    fn accepted(chunk_hash: Multihash, index: u32, peer_id: &PeerId, proof: &[u8]) -> bool {
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
        chunk_hash: Multihash,
        index: u32,
        public_key: &PublicKey,
        proof: &[u8],
    ) -> bool {
        // TODO check high/low watermark?
        let mut input = chunk_hash.to_bytes();
        input.extend(&index.to_be_bytes());
        public_key.verify(&input, proof)
            && Self::accepted(
                chunk_hash,
                index,
                &PeerId::from_public_key(public_key),
                proof,
            )
    }
}

impl Chunk {
    fn gossip_members(&self) -> Vec<proto::Member> {
        self.members
            .iter()
            .map(|(key, (index, addr))| proto::Member::new_gossip(*index, key, addr))
            .collect()
    }

    // duplicated code
    // i don't fucking care
    fn invite_members(&self) -> Vec<proto::Member> {
        self.members
            .iter()
            .map(|(key, (index, addr))| {
                proto::Member::new(*index, key, addr, self.proofs[index].1.clone())
            })
            .collect()
    }
}
