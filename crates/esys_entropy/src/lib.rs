use std::{future::Future, mem::take, ops::ControlFlow};

use libp2p::{
    core::{muxing::StreamMuxerBox, transport, ConnectedPoint},
    futures::StreamExt,
    identify,
    identity::Keypair,
    kad::{store::MemoryStore, Kademlia, KademliaEvent, QueryResult},
    multiaddr,
    swarm::{NetworkBehaviour, SwarmEvent, THandlerErr},
    Multiaddr, PeerId, Swarm,
};
use tokio::{
    select, spawn,
    sync::{mpsc, oneshot},
    task::JoinHandle,
};

#[derive(NetworkBehaviour)]
pub struct App {
    identify: identify::Behaviour,
    kad: Kademlia<MemoryStore>,
}

#[derive(Clone)]
pub struct AppControl {
    ingress: mpsc::UnboundedSender<
        Box<dyn FnOnce(&mut Swarm<App>, &mut Vec<(AppObserver, oneshot::Sender<()>)>) + Send>,
    >,
}

pub type AppObserver = Box<dyn FnMut(&ControlEvent, &mut Swarm<App>) -> ControlFlow<()> + Send>;
pub type ControlEvent = SwarmEvent<AppEvent, THandlerErr<App>>;

impl App {
    pub fn run(
        name: impl ToString,
        transport: transport::Boxed<(PeerId, StreamMuxerBox)>,
        keypair: Keypair,
        addr: impl TryInto<Multiaddr>,
    ) -> (JoinHandle<Swarm<Self>>, AppControl) {
        let id = PeerId::from_public_key(&keypair.public());
        let app = Self {
            identify: identify::Behaviour::new(identify::Config::new(
                "/entropy/0.1.0".into(),
                keypair.public(),
            )),
            kad: Kademlia::new(id, MemoryStore::new(id)),
        };
        let mut swarm = Swarm::with_tokio_executor(transport, app, id);
        swarm
            .listen_on(addr.try_into().map_err(|_| ()).unwrap())
            .unwrap();
        let mut ingress = mpsc::unbounded_channel();
        let control = AppControl { ingress: ingress.0 };
        let name = name.to_string();
        let handle = spawn(async move {
            let mut observers = Vec::new();
            loop {
                select! {
                    action = ingress.1.recv() => {
                        let Some(action) = action else { return swarm };
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

    pub fn serve_kad(&mut self) {
        let _ = self.subscribe(|event, swarm| {
            if let SwarmEvent::Behaviour(AppEvent::Identify(identify::Event::Received {
                peer_id,
                info,
            })) = event
            {
                swarm.behaviour_mut().kad.add_address(
                    &peer_id,
                    info.listen_addrs
                        .iter()
                        .find(|addr| is_global(*addr))
                        .unwrap()
                        .to_owned(),
                );
            }
            ControlFlow::Continue(())
        });
    }

    pub async fn boostrap(&mut self, service: Multiaddr) {
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
    }
}

fn is_global(addr: &Multiaddr) -> bool {
    match addr.iter().nth(0) {
        Some(multiaddr::Protocol::Memory(_)) => true,
        Some(multiaddr::Protocol::Ip4(addr)) => !addr.is_private() && !addr.is_loopback(),
        _ => false,
    }
}
