use std::{mem::take, net::Ipv4Addr, time::Duration};

use clap::Parser;
use esys_entropy::App;
use libp2p::{
    core::upgrade::Version::V1,
    identity::Keypair,
    multiaddr::{multiaddr, Protocol},
    tcp, Transport,
};
use tokio::time::sleep;

#[derive(Parser)]
struct Cli {
    #[clap(long)]
    ip: Ipv4Addr,
    #[clap(long)]
    bootstrap_service: bool,
    #[clap(long)]
    service_ip: Option<Ipv4Addr>,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    let id_keys = Keypair::generate_ed25519();
    let transport = tcp::tokio::Transport::new(tcp::Config::default().nodelay(true))
        .upgrade(V1)
        .authenticate(libp2p::noise::NoiseAuthenticated::xx(&id_keys).unwrap())
        .multiplex(libp2p::yamux::YamuxConfig::default())
        .boxed();
    let (handle, control) = App::run("", transport, id_keys);
    let mut first_addr = true;
    control.serve_listen(move |addr| {
        addr.replace(0, |protocol| {
            assert!(matches!(protocol, Protocol::Ip4(_)));
            if take(&mut first_addr) {
                Some(Protocol::Ip4(cli.ip))
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

    if cli.bootstrap_service {
        handle.await.unwrap();
    } else {
        control
            .boostrap(multiaddr!(Ip4(cli.service_ip.unwrap()), Tcp(8500u16)))
            .await;
        sleep(Duration::from_secs(5)).await;
        control.register().await;
        handle.await.unwrap();
    }
}
