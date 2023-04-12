use std::{mem::take, net::Ipv4Addr, pin::pin, time::Duration};

use clap::Parser;
use esys_entropy::{App, AppConfig, Base, BaseHandle};
use libp2p::{
    core::upgrade::Version::V1,
    identity::Keypair,
    multiaddr::{multiaddr, Protocol},
    tcp, Multiaddr, Swarm, Transport,
};
use rand::{thread_rng, Rng};
use tokio::{signal::ctrl_c, spawn, task::JoinHandle, time::sleep};
use tracing::{debug_span, Instrument};
use tracing_subscriber::{fmt::format::FmtSpan, EnvFilter};

#[derive(Parser)]
struct Cli {
    #[clap(long)]
    ip: Ipv4Addr,
    #[clap(long)]
    bootstrap_service: bool,
    #[clap(long)]
    service_ip: Option<Ipv4Addr>,
    #[clap(short, default_value_t = 1)]
    n: usize,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE)
        .init();
    let cli = Cli::parse();

    if cli.bootstrap_service {
        let app = start_base(&cli).await;
        ctrl_c().await.unwrap();
        drop(app.handle);
        app.event_loop.await.unwrap();
    } else {
        let mut tasks = Vec::new();
        for _ in 0..cli.n {
            let base = start_base(&cli).await;
            let task = spawn(async move {
                let delay = thread_rng().gen_range(0..5 * 1000);
                // up to 5s random delay + up to 10s bootstrap latency + safe margin + still want random delay
                let register_delay = pin!(sleep(Duration::from_millis(20 * 1000 + delay)));

                sleep(Duration::from_millis(delay)).await;
                base.handle
                    .boostrap(multiaddr!(Ip4(cli.service_ip.unwrap()), Tcp(8500u16)))
                    .instrument(debug_span!("bootstrap", addr = %base.addr))
                    .await;

                register_delay.await;
                base.handle.register().await;
                base
            });
            tasks.push(task);
        }

        let mut bases = Vec::new();
        for task in tasks {
            bases.push(task.await.unwrap());
        }
        tracing::info!("peers register done");

        let mut base_loops = Vec::new();
        let mut app_controls = Vec::new();
        let mut app_loops = Vec::new();
        for base in bases {
            base_loops.push(base.event_loop);
            let mut app = App::new(
                base.handle,
                base.keypair,
                base.addr,
                AppConfig {
                    invite_count: 0,
                    chunk_k: 0,
                    chunk_n: 0,
                    fragment_k: 0,
                    fragment_n: 0,
                    fragment_size: 0,
                    watermark_interval: Duration::ZERO,
                    membership_interval: Duration::ZERO,
                    gossip_interval: Duration::ZERO,
                    invite_interval: Duration::ZERO,
                },
            );
            app_controls.push(app.control());
            let app_loop = spawn(async move { app.serve().await });
            app_loops.push(app_loop);
        }

        ctrl_c().await.unwrap();
        for app_control in app_controls {
            app_control.close();
        }
        for app_loop in app_loops {
            app_loop.await.unwrap();
        }
        for event_loop in base_loops {
            event_loop.await.unwrap();
        }
    }
}

struct StartBase {
    event_loop: JoinHandle<Swarm<Base>>,
    handle: BaseHandle,
    keypair: Keypair,
    addr: Multiaddr,
}

async fn start_base(cli: &Cli) -> StartBase {
    let id_keys = Keypair::generate_ed25519();
    let transport = tcp::tokio::Transport::new(tcp::Config::default().nodelay(true))
        .upgrade(V1)
        .authenticate(libp2p::noise::NoiseAuthenticated::xx(&id_keys).unwrap())
        .multiplex(libp2p::yamux::YamuxConfig::default())
        .boxed();
    let (event_loop, handle) = Base::run("", transport, &id_keys);
    let mut first_addr = true;
    let ip = cli.ip;
    let notify = handle.serve_add_external_address(move |addr| {
        addr.replace(0, |protocol| {
            assert!(matches!(protocol, Protocol::Ip4(_)));
            if take(&mut first_addr) {
                Some(Protocol::Ip4(ip))
            } else {
                None
            }
        })
    });
    handle.serve_kad_add_address();
    handle.listen_on(multiaddr!(
        Ip4(0),
        Tcp(if cli.bootstrap_service { 8500u16 } else { 0 })
    ));
    notify.notified().await;
    let addr = handle
        .ingress_wait(|swarm| swarm.external_addresses().next().unwrap().addr.clone())
        .await;
    StartBase {
        event_loop,
        handle,
        keypair: id_keys,
        addr,
    }
}
