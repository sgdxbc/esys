use std::{future::Future, mem::take, ops::ControlFlow, sync::Arc, time::Duration};

use libp2p::{
    core::{muxing::StreamMuxerBox, transport, ConnectedPoint},
    futures::StreamExt,
    identify::{self, Behaviour as Identify},
    identity::Keypair,
    kad::{
        kbucket, record::Key, store::MemoryStore, GetClosestPeersError, GetRecordError,
        GetRecordOk, Kademlia, KademliaEvent, PutRecordError, QueryResult, Quorum, Record,
    },
    multiaddr,
    multihash::Multihash,
    request_response::{ProtocolSupport, ResponseChannel},
    swarm::{
        dial_opts::DialOpts,
        AddressScore, NetworkBehaviour as NetworkBehavior, SwarmBuilder,
        SwarmEvent::{self, Behaviour as Behavior},
        THandlerErr as HandlerErr,
    },
    Multiaddr, PeerId, Swarm,
};

use rand::{thread_rng, Rng};
use tokio::{
    select, spawn,
    sync::{mpsc, oneshot, Notify},
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
    pub kad: Kademlia<MemoryStore>,
    pub rpc: crate::rpc::Behavior,
}

impl Base {
    pub fn rpc_ensure_address(&mut self, peer_id: &PeerId, addr: Multiaddr) {
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
        more_replication: bool,
    ) -> (JoinHandle<Swarm<Self>>, BaseHandle) {
        let id = PeerId::from_public_key(&keypair.public());
        let app = Self {
            identify: Identify::new(
                identify::Config::new("/entropy/0.1.0".into(), keypair.public())
                    // in our setup the info never change
                    .with_interval(Duration::from_secs(86400)),
            ),
            kad: Kademlia::with_config(
                id,
                MemoryStore::with_config(
                    id,
                    libp2p::kad::record::store::MemoryStoreConfig {
                        max_records: usize::MAX,
                        max_value_bytes: usize::MAX,
                        ..Default::default()
                    },
                ),
                {
                    let mut config = libp2p::kad::KademliaConfig::default();
                    // config.set_query_timeout(Duration::from_secs(8));
                    config.set_max_packet_size(1 << 30);
                    if more_replication {
                        config.set_replication_interval(Some(Duration::from_secs(30)));
                    }
                    config
                },
            ),
            // kad: Kademlia::new(id, MemoryStore::new(id)),
            rpc: crate::rpc::Behavior::new(
                Default::default(),
                [(crate::rpc::Protocol, ProtocolSupport::Full)],
                {
                    let mut rpc_config = libp2p::request_response::Config::default();
                    rpc_config.set_request_timeout(std::time::Duration::from_secs(60));
                    rpc_config
                },
                // Default::default(),
            ),
        };
        let mut swarm = SwarmBuilder::with_tokio_executor(transport, app, id)
            .max_negotiating_inbound_streams(65536) // hope this works
            .build();
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
        // if
        self.ingress
            .send(Box::new(|swarm, _| action(swarm)))
            .map_err(|_| ())
            .unwrap();
        //     .is_err()
        // {
        //     tracing::warn!("fail to ingress");
        // }
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
    ) -> Arc<Notify> {
        let notify = Arc::new(Notify::new());
        let s = self.subscribe({
            let notify = notify.clone();
            move |event, swarm| {
                if let SwarmEvent::NewListenAddr { address, .. } = event.as_ref().unwrap() {
                    if let Some(address) = into_external(address) {
                        tracing::debug!(peer_id = %swarm.local_peer_id(), %address, "add external");
                        swarm.add_external_address(address, AddressScore::Infinite);
                        notify.notify_one();
                    }
                    *event = None;
                }
                ControlFlow::<()>::Continue(())
            }
        });
        drop(s);
        notify
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

    pub fn serve_kad_refresh(&self, interval: Duration) -> JoinHandle<()> {
        let s = self.subscribe(move |event, swarm| {
            if let SwarmEvent::OutgoingConnectionError {
                peer_id: Some(peer_id),
                ..
            } = event.as_ref().unwrap()
            {
                // tracing::debug!(%peer_id, "evict peer");
                swarm.behaviour_mut().kad.remove_peer(peer_id);
            }
            ControlFlow::<()>::Continue(())
        });
        drop(s);
        let base = self.clone();
        spawn(async move {
            let initial_backoff = thread_rng().gen_range(Duration::ZERO..interval);
            sleep(initial_backoff).await;
            loop {
                sleep(interval).await;
                base.ingress_wait(|swarm| {
                    let mut peers = Vec::new();
                    for kbucket in swarm.behaviour_mut().kad.kbuckets() {
                        for entry in kbucket.iter() {
                            peers.push((
                                entry.node.key.preimage().clone(),
                                entry.node.value.first().clone(),
                            ));
                        }
                    }
                    for (peer_id, addr) in peers {
                        if swarm.is_connected(&peer_id) {
                            continue;
                        }
                        let opts = DialOpts::peer_id(peer_id).addresses(vec![addr]).build();
                        swarm.dial(opts).unwrap();
                    }
                })
                .await
            }
        })
    }

    pub async fn cancel_queries(&self) {
        self.ingress_wait(|swarm| {
            for mut query in swarm.behaviour_mut().kad.iter_queries_mut() {
                query.finish();
            }
        })
        .await;
    }

    pub fn cancel_observers(&self) {
        self.ingress
            .send(Box::new(|_, observers| observers.clear()))
            .map_err(|_| ())
            .unwrap();
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
                    // is this expected?
                    Ok(GetRecordOk::FinishedWithNoAdditionalRecord { .. })
                    | Err(GetRecordError::NotFound { .. }) => None,
                    Err(GetRecordError::Timeout { .. }) => {
                        tracing::warn!(?id, "query address timeout");
                        None
                    }
                    result => unreachable!(
                        "either FoundRecord or NotFound should be delivered before {result:?}"
                    ),
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
        let backoff = rand::thread_rng().gen_range(Duration::ZERO..Duration::from_millis(1 * 1000));
        tokio::time::sleep(backoff).await;
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
                    let result = match result {
                        Ok(result) => result,
                        Err(GetClosestPeersError::Timeout { .. }) => {
                            tracing::warn!(?id, "query timeout");
                            return ControlFlow::Break(Default::default());
                        }
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

    pub fn response_ok(&self, channel: ResponseChannel<crate::rpc::proto::Response>) {
        self.ingress(move |swarm| {
            swarm
                .behaviour_mut()
                .rpc
                .send_response(
                    channel,
                    crate::rpc::proto::Response::from(crate::rpc::proto::Ok {}),
                )
                .unwrap()
        })
    }
}

fn is_global(addr: &Multiaddr) -> bool {
    match addr.iter().next() {
        Some(multiaddr::Protocol::Memory(_)) => true,
        Some(multiaddr::Protocol::Ip4(addr)) => !addr.is_private() && !addr.is_loopback(),
        _ => false,
    }
}
