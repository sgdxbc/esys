use std::{
    convert::Infallible,
    env,
    fmt::Debug,
    mem::replace,
    task::Poll,
    time::{Duration, Instant},
};

use futures::{AsyncReadExt, AsyncWriteExt};
use libp2p::{
    core::upgrade::{ReadyUpgrade, Version::V1},
    futures::{future::BoxFuture, FutureExt, StreamExt},
    identity::Keypair,
    swarm::{
        handler::{ConnectionEvent, FullyNegotiatedInbound, FullyNegotiatedOutbound},
        ConnectionHandler, ConnectionHandlerEvent, KeepAlive, NetworkBehaviour,
        NetworkBehaviourAction, SubstreamProtocol, SwarmEvent,
    },
    tcp::{self, tokio::Transport},
    Multiaddr, PeerId, Swarm, Transport as _,
};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    tracing_subscriber::fmt::init();

    #[derive(Debug)]
    enum Task {
        Ping(Multiaddr),
        Pong,
    }
    let task = match env::args().nth(1).as_deref() {
        Some(addr) => Task::Ping(addr.parse().unwrap()),
        None => Task::Pong,
    };

    let id_keys = Keypair::generate_ed25519();
    let id = PeerId::from_public_key(&id_keys.public());
    println!("id {id} task {task:?}");
    let transport = Transport::new(tcp::Config::default().nodelay(true))
        .upgrade(V1)
        .authenticate(libp2p::noise::NoiseAuthenticated::xx(&id_keys).unwrap())
        // .authenticate(libp2p::tls::Config::new(&id_keys).unwrap())
        // .authenticate(libp2p::plaintext::PlainText2Config {
        //     local_public_key: id_keys.public(),
        // })
        // .multiplex(libp2p::mplex::MplexConfig::new())
        .multiplex(libp2p::yamux::YamuxConfig::default())
        .boxed();
    let mut swarm = Swarm::with_tokio_executor(transport, Behaviour::default(), id);
    match task {
        Task::Pong => {
            swarm
                .listen_on("/ip4/0.0.0.0/tcp/0".parse().unwrap())
                .unwrap();
        }
        Task::Ping(addr) => swarm.dial(addr).unwrap(),
    }
    while let Some(event) = swarm.next().await {
        match event {
            SwarmEvent::NewListenAddr { address, .. } => println!("listen {address}"),
            SwarmEvent::ConnectionEstablished {
                peer_id,
                endpoint,
                established_in,
                ..
            } => {
                println!("connection established to {peer_id} in {established_in:?}");
                println!("  endpoint {endpoint:?}");
            }
            SwarmEvent::Behaviour(event) => {
                println!("{event:?}");
                break;
            }
            _ => {}
        }
    }
}

#[derive(Default)]
struct Behaviour(Option<OutEvent>);

impl NetworkBehaviour for Behaviour {
    type ConnectionHandler = Handler;
    type OutEvent = OutEvent;

    fn on_swarm_event(&mut self, _event: libp2p::swarm::FromSwarm<Self::ConnectionHandler>) {}

    fn on_connection_handler_event(
        &mut self,
        _peer_id: libp2p::PeerId,
        _connection_id: libp2p::swarm::ConnectionId,
        event: libp2p::swarm::THandlerOutEvent<Self>,
    ) {
        self.0 = Some(event);
    }

    fn poll(
        &mut self,
        _cx: &mut std::task::Context<'_>,
        _params: &mut impl libp2p::swarm::PollParameters,
    ) -> Poll<NetworkBehaviourAction<Self::OutEvent, libp2p::swarm::THandlerInEvent<Self>>> {
        match self.0.take() {
            Some(event) => Poll::Ready(NetworkBehaviourAction::GenerateEvent(event)),
            None => Poll::Pending,
        }
    }

    fn handle_established_inbound_connection(
        &mut self,
        _connection_id: libp2p::swarm::ConnectionId,
        _peer: PeerId,
        _local_addr: &Multiaddr,
        _remote_addr: &Multiaddr,
    ) -> Result<libp2p::swarm::THandler<Self>, libp2p::swarm::ConnectionDenied> {
        Ok(Handler::WaitOpen)
    }

    fn handle_established_outbound_connection(
        &mut self,
        _connection_id: libp2p::swarm::ConnectionId,
        _peer: PeerId,
        _addr: &Multiaddr,
        _role_override: libp2p::core::Endpoint,
    ) -> Result<libp2p::swarm::THandler<Self>, libp2p::swarm::ConnectionDenied> {
        Ok(Handler::Open)
    }
}

enum Handler {
    Open,
    WaitOpen,
    Ping(BoxFuture<'static, OutEvent>),
    Pong(BoxFuture<'static, ()>),
    Closing,
}

#[derive(Debug)]
enum OutEvent {
    Pinged(u32),
}

impl ConnectionHandler for Handler {
    type InboundProtocol = ReadyUpgrade<&'static [u8]>;
    type OutboundProtocol = ReadyUpgrade<&'static [u8]>;
    type InEvent = ();
    type OutEvent = OutEvent;
    type Error = Infallible;
    type InboundOpenInfo = ();
    type OutboundOpenInfo = ();

    fn listen_protocol(&self) -> SubstreamProtocol<Self::InboundProtocol, Self::InboundOpenInfo> {
        SubstreamProtocol::new(ReadyUpgrade::new(b"/esys-pingpong/0.1.0"), ())
    }

    fn connection_keep_alive(&self) -> KeepAlive {
        match self {
            Self::Closing => KeepAlive::No,
            _ => KeepAlive::Yes,
        }
    }

    fn poll(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<
        libp2p::swarm::ConnectionHandlerEvent<
            Self::OutboundProtocol,
            Self::OutboundOpenInfo,
            Self::OutEvent,
            Self::Error,
        >,
    > {
        match self {
            Self::Open => {
                println!("request outbound substream");
                *self = Self::WaitOpen;
                Poll::Ready(ConnectionHandlerEvent::OutboundSubstreamRequest {
                    protocol: SubstreamProtocol::new(
                        ReadyUpgrade::new(b"/esys-pingpong/0.1.0"),
                        (),
                    ),
                })
            }
            Self::WaitOpen | Self::Closing => Poll::Pending,
            Self::Pong(future) => {
                if future.poll_unpin(cx).is_ready() {
                    println!("closing");
                    *self = Self::Closing;
                }
                Poll::Pending
            }
            Self::Ping(future) => match future.poll_unpin(cx) {
                Poll::Ready(event) => {
                    *self = Self::Closing;
                    Poll::Ready(ConnectionHandlerEvent::Custom(event))
                }
                Poll::Pending => Poll::Pending,
            },
        }
    }

    fn on_behaviour_event(&mut self, _event: Self::InEvent) {}

    fn on_connection_event(
        &mut self,
        event: ConnectionEvent<
            Self::InboundProtocol,
            Self::OutboundProtocol,
            Self::InboundOpenInfo,
            Self::OutboundOpenInfo,
        >,
    ) {
        match event {
            ConnectionEvent::FullyNegotiatedInbound(FullyNegotiatedInbound {
                protocol: mut stream,
                info: (),
            }) => {
                println!("fully negotiated");
                let prev = replace(
                    self,
                    Self::Pong(Box::pin(async move {
                        let mut buf = [0; 4];
                        while let Ok(()) = stream.read_exact(&mut buf).await {
                            let _ = stream.write_all(&buf).await;
                            let _ = stream.flush().await;
                        }
                        println!("pinger disconnected");
                        let _ = stream.close().await;
                    })),
                );
                assert!(matches!(prev, Self::WaitOpen));
            }
            ConnectionEvent::FullyNegotiatedOutbound(FullyNegotiatedOutbound {
                protocol: mut stream,
                info: (),
            }) => {
                println!("fully negotiated");
                let prev = replace(
                    self,
                    Self::Ping(Box::pin(async move {
                        let start = Instant::now();
                        let mut count = 0u32;
                        while Instant::now() - start < Duration::from_secs(10) {
                            let ping = async {
                                stream.write_all(&count.to_ne_bytes()).await?;
                                stream.flush().await?;
                                stream.read_exact(&mut [0; 4]).await?;
                                futures::io::Result::Ok(())
                            };
                            ping.await.unwrap();
                            count += 1;
                        }
                        stream.close().await.unwrap();
                        OutEvent::Pinged(count)
                    })),
                );
                assert!(matches!(prev, Self::WaitOpen));
            }
            _ => panic!("unexpected connection event"),
        }
    }
}
