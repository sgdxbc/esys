use std::{sync::Arc, time::Duration};

use esys_entropy::Base;
use libp2p::{
    core::{transport::MemoryTransport, upgrade::Version::V1},
    identity::Keypair,
    noise::NoiseAuthenticated,
    yamux::YamuxConfig,
    PeerId, Transport,
};
use tokio::{
    spawn,
    sync::{Barrier, Mutex},
    task::yield_now,
    time::sleep,
};
use tracing::Instrument;
use tracing_subscriber::{fmt::format::FmtSpan, EnvFilter};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE)
        .init();

    let server_keypair = Keypair::generate_ed25519();
    let transport = MemoryTransport::new()
        .upgrade(V1)
        .authenticate(NoiseAuthenticated::xx(&server_keypair).unwrap())
        .multiplex(YamuxConfig::default())
        .boxed();
    let (_handle, server_control) = Base::run("bootstrap", transport, &server_keypair);
    server_control.serve_add_external_address(|addr| Some(addr.clone()));
    server_control.serve_kad_add_address();
    server_control.listen_on("/memory/1".parse().unwrap());

    let n = 20;
    let register_barrier = Arc::new(Barrier::new(n));
    let exit_barrier = Arc::new(Barrier::new(n + 1));
    let peer_ids = Arc::new(Mutex::new(Vec::new()));
    let peers = (0..n)
        .map(|i| {
            let peer_ids = peer_ids.clone();
            let register_barrier = register_barrier.clone();
            let exit_barrier = exit_barrier.clone();
            spawn(async move {
                let key_pair = Keypair::generate_ed25519();
                let peer_id = PeerId::from_public_key(&key_pair.public());
                let transport = MemoryTransport::new()
                    .upgrade(V1)
                    .authenticate(NoiseAuthenticated::xx(&key_pair).unwrap())
                    .multiplex(YamuxConfig::default())
                    .boxed();
                let (_handle, control) = Base::run(format!("client-{i}"), transport, &key_pair);
                control.serve_add_external_address(|addr| Some(addr.clone()));
                control.serve_kad_add_address();
                control.listen_on("/memory/0".parse().unwrap());

                sleep(Duration::from_millis(i as u64 * 10)).await;
                control.boostrap("/memory/1".parse().unwrap()).await;
                sleep(Duration::from_millis(300)).await; // wait 30 * 10ms until enough peers (~30) join to form a quorum
                control.register().await;

                peer_ids.lock().await.push(peer_id);
                if register_barrier.wait().await.is_leader() {
                    for peer_id in &*peer_ids.lock().await {
                        let span = tracing::info_span!("query", %peer_id);
                        let result = control
                            .query((*peer_id).into(), 3)
                            .instrument(span.clone())
                            .await;
                        tracing::info!(parent: &span, result = ?&result);
                    }
                }

                exit_barrier.wait().await;
                yield_now().await;
            })
        })
        .collect::<Vec<_>>();

    exit_barrier.wait().await;
    for peer in peers {
        peer.await.unwrap()
    }
}
