use std::{mem::take, net::Ipv4Addr, ops::Range, pin::pin, time::Duration};

use clap::Parser;
use esys_entropy::{App, AppConfig, Base, BaseHandle};
use libp2p::{
    core::upgrade::Version::V1,
    identity::Keypair,
    multiaddr::{multiaddr, Protocol},
    tcp, Multiaddr, Swarm, Transport,
};
use rand::{thread_rng, Rng, RngCore};
use tokio::{signal::ctrl_c, spawn, task::JoinHandle, time::sleep};
use tracing::{debug_span, info_span, Instrument};
use tracing_subscriber::{fmt::format::FmtSpan, EnvFilter};

#[derive(Parser)]
struct Cli {
    #[clap(long)]
    ip: Ipv4Addr,
    #[clap(long)]
    bootstrap_service: bool,
    #[clap(long)]
    put: bool,
    #[clap(long)]
    service_ip: Option<Ipv4Addr>,
    #[clap(short, default_value_t = 1)]
    n: usize,

    #[clap(long, default_value_t = 100)]
    chunk_k: usize,
    #[clap(long, default_value_t = 100)]
    chunk_n: usize,
    #[clap(long, default_value_t = 64)]
    fragment_k: usize,
    #[clap(long, default_value_t = 100)]
    fragment_n: usize,
    #[clap(long, default_value_t = 0)]
    fragment_size: usize,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE)
        .init();
    let cli = Cli::parse();

    if cli.bootstrap_service {
        let app = start_base(&cli, "service").await;
        ctrl_c().await.unwrap();
        drop(app.handle);
        app.event_loop.await.unwrap();
    } else {
        let config = AppConfig {
            invite_count: 1,
            chunk_k: cli.chunk_k,
            chunk_n: cli.chunk_n,
            fragment_k: cli.fragment_k,
            fragment_n: cli.fragment_n,
            fragment_size: if cli.fragment_size == 0 {
                (1 << 30) / cli.chunk_k / cli.fragment_k
            } else {
                cli.fragment_size
            },
            watermark_interval: Duration::from_secs(86400),
            membership_interval: Duration::from_secs(86400),
            gossip_interval: Duration::from_secs(86400),
            invite_interval: Duration::from_secs(600),
        };

        let init_base =
            |base: StartBase, delay_range: Range<Duration>, register_after: Duration| {
                spawn(async move {
                    let delay = thread_rng().gen_range(delay_range);
                    let register_delay = pin!(sleep(register_after + delay));

                    sleep(delay).await;
                    base.handle
                        .boostrap(multiaddr!(Ip4(cli.service_ip.unwrap()), Tcp(8500u16)))
                        .instrument(debug_span!("bootstrap", addr = %base.addr))
                        .await;

                    register_delay.await;
                    base.handle.register().await;
                    base
                })
            };

        if cli.put {
            let base = init_base(
                start_base(&cli, "put").await,
                Duration::ZERO..Duration::from_millis(1),
                Duration::ZERO,
            )
            .await
            .unwrap();
            let mut data = vec![0; config.fragment_size * config.fragment_k * config.chunk_k];
            let mut app = App::new(base.handle, base.keypair, base.addr, config);
            let control = app.control();
            let app_loop = spawn(async move { app.serve().await });
            thread_rng().fill_bytes(&mut data);
            async {
                let mut put_chunks = control.put(data);
                while let Some(chunk_hash) = put_chunks.recv().await {
                    tracing::info!("put chunk {chunk_hash:02x?}");
                }
            }
            .instrument(info_span!("put"))
            .await;
            control.close();
            app_loop.await.unwrap();
            base.event_loop.await.unwrap();
        } else {
            let mut tasks = Vec::new();
            for i in 0..cli.n {
                tasks.push(init_base(
                    start_base(&cli, format!("normal-{i}")).await,
                    // wait for the farest peers
                    // Duration::ZERO..Duration::from_millis(20 * 1000),
                    Duration::ZERO..Duration::from_millis(5 * 1000),
                    // up to 20s random delay diff + up to 40s bootstrap latency
                    // Duration::from_millis(80 * 1000),
                    Duration::from_millis(30 * 1000),
                ));
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
                let mut app = App::new(base.handle, base.keypair, base.addr, config.clone());
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
}

struct StartBase {
    event_loop: JoinHandle<Swarm<Base>>,
    handle: BaseHandle,
    keypair: Keypair,
    addr: Multiaddr,
}

async fn start_base(cli: &Cli, name: impl ToString) -> StartBase {
    let id_keys = Keypair::generate_ed25519();
    let transport = tcp::tokio::Transport::new(tcp::Config::default().nodelay(true))
        .upgrade(V1)
        .authenticate(libp2p::noise::NoiseAuthenticated::xx(&id_keys).unwrap())
        .multiplex(libp2p::yamux::YamuxConfig::default())
        .boxed();
    let (event_loop, handle) = Base::run(name, transport, &id_keys);
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
