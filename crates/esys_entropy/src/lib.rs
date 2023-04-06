mod behavior;

use std::{future::Future, mem::take, ops::ControlFlow};

use libp2p::{
    core::{muxing::StreamMuxerBox, transport, ConnectedPoint},
    futures::StreamExt,
    identify,
    identity::Keypair,
    kad::{
        kbucket, record::Key, store::MemoryStore, GetRecordOk, Kademlia, KademliaEvent,
        PutRecordError, QueryResult, Quorum, Record,
    },
    multiaddr,
    multihash::Multihash,
    request_response::ProtocolSupport,
    swarm::{
        AddressScore, NetworkBehaviour as NetworkBehavior, SwarmBuilder, SwarmEvent,
        THandlerErr as HandlerErr,
    },
    Multiaddr, PeerId, Swarm,
};
use tokio::{
    select, spawn,
    sync::{mpsc, oneshot},
    task::JoinHandle,
};

#[derive(NetworkBehavior)]
pub struct App {
    identify: identify::Behaviour,
    kad: Kademlia<MemoryStore>,
    entropy: behavior::Behavior,
}

#[derive(Clone)]
pub struct AppControl {
    ingress: mpsc::UnboundedSender<
        Box<dyn FnOnce(&mut Swarm<App>, &mut Vec<(AppObserver, oneshot::Sender<()>)>) + Send>,
    >,
}

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
        let control = AppControl { ingress: ingress.0 };
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
