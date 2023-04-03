use std::{mem::take, net::Ipv4Addr, time::Duration};

use clap::Parser;
use esys_entropy::{App, AppControl};
use libp2p::{
    core::upgrade::Version::V1,
    identity::Keypair,
    multiaddr::{multiaddr, Protocol},
    tcp, Swarm, Transport,
};
use rand::{thread_rng, Rng};
use tokio::{signal::ctrl_c, spawn, task::JoinHandle, time::sleep};

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
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    if cli.bootstrap_service {
        let (handle, control) = start_app(&cli);
        // handle.await.unwrap();
        ctrl_c().await.unwrap();
        drop(control);
        handle.await.unwrap();
    } else {
        let mut handles = Vec::new();
        let mut tasks = Vec::new();
        for _ in 0..cli.n {
            let (handle, control) = start_app(&cli);
            handles.push(handle);
            let task = spawn(async move {
                let delay = thread_rng().gen_range(0..5 * 1000);
                sleep(Duration::from_millis(delay)).await;
                control
                    .boostrap(multiaddr!(Ip4(cli.service_ip.unwrap()), Tcp(8500u16)))
                    .await;
                sleep(Duration::from_millis(5000)).await;
                control.register().await;
                control
            });
            tasks.push(task);
        }

        let mut controls = Vec::new();
        for task in tasks {
            controls.push(task.await.unwrap());
        }
        tracing::info!("peers register done");

        ctrl_c().await.unwrap();
        drop(controls);
        for handle in handles {
            handle.await.unwrap();
        }
    }
}

fn start_app(cli: &Cli) -> (JoinHandle<Swarm<App>>, AppControl) {
    let id_keys = Keypair::generate_ed25519();
    let transport = tcp::tokio::Transport::new(tcp::Config::default().nodelay(true))
        .upgrade(V1)
        .authenticate(libp2p::noise::NoiseAuthenticated::xx(&id_keys).unwrap())
        .multiplex(libp2p::yamux::YamuxConfig::default())
        .boxed();
    let (handle, control) = App::run("", transport, id_keys);
    let mut first_addr = true;
    let ip = cli.ip;
    control.serve_listen(move |addr| {
        addr.replace(0, |protocol| {
            assert!(matches!(protocol, Protocol::Ip4(_)));
            if take(&mut first_addr) {
                Some(Protocol::Ip4(ip))
            } else {
                None
            }
        })
    });
    control.serve_kad();
    control.listen_on(multiaddr!(
        Ip4(0),
        Tcp(if cli.bootstrap_service { 8500u16 } else { 0 })
    ));
    (handle, control)
}
