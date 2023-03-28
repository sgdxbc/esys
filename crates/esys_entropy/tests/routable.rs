use std::{sync::Arc, time::Duration};

use esys_entropy::{App, AppControl};
use libp2p::{
    core::{transport::MemoryTransport, upgrade::Version::V1},
    identity::Keypair,
    noise::NoiseAuthenticated,
    yamux::YamuxConfig,
    PeerId, Transport,
};
use tokio::{spawn, sync::Mutex};

#[tokio::test]
async fn get_all_peers() {
    tracing_subscriber::fmt::init();

    let server_keypair = Keypair::generate_ed25519();
    let transport = MemoryTransport::new()
        .upgrade(V1)
        .authenticate(NoiseAuthenticated::xx(&server_keypair).unwrap())
        .multiplex(YamuxConfig::default())
        .boxed();
    let (_handle, mut server_control) =
        App::run("bootstrap", transport, server_keypair, "/memory/1");
    server_control.serve_kad();

    let peer_ids = Arc::new(Mutex::new(Vec::new()));
    let peers = (0..4)
        .map(|i| {
            let peer_ids = peer_ids.clone();
            spawn(async move {
                let key_pair = Keypair::generate_ed25519();
                let peer_id = PeerId::from_public_key(&key_pair.public());
                peer_ids.lock().await.push(peer_id);
                let transport = MemoryTransport::new()
                    .upgrade(V1)
                    .authenticate(NoiseAuthenticated::xx(&key_pair).unwrap())
                    .multiplex(YamuxConfig::default())
                    .boxed();
                let (_handle, mut control) =
                    App::run(format!("client-{i}"), transport, key_pair, "/memory/0");
                control.serve_kad();
                control.boostrap("/memory/1".parse().unwrap()).await;

                tokio::time::sleep(Duration::from_secs(1)).await;
                //
            })
        })
        .collect::<Vec<_>>();

    for peer in peers {
        peer.await.unwrap()
    }
}

// async fn reach_all(control: &AppControl, peer_ids: &[PeerId]) {
//     let mut i = 0;
// }
