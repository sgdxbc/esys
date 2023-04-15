use std::{
    mem::take,
    net::Ipv4Addr,
    ops::{ControlFlow, Range},
    pin::pin,
    sync::Arc,
    time::{Duration, Instant},
};

use clap::Parser;
use esys_entropy::{App, AppConfig, AppControl, Base, BaseEvent, BaseHandle};
use esys_wirehair::WirehairDecoder;
use libp2p::{
    bandwidth::BandwidthSinks,
    core::upgrade::Version::V1,
    identity::Keypair,
    kad::{GetRecordOk, KademliaEvent, QueryResult, Record},
    multiaddr::{multiaddr, Protocol},
    multihash::{Code, MultihashDigest},
    swarm::SwarmEvent,
    tcp, Multiaddr, Swarm, Transport, TransportExt,
};
use rand::{thread_rng, Rng, RngCore};
use rand_distr::{Distribution, Poisson};
use tokio::{fs, select, signal::ctrl_c, spawn, task::JoinHandle, time::sleep};
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

    #[clap(long, default_value_t = 8)]
    chunk_k: usize,
    #[clap(long, default_value_t = 10)]
    chunk_n: usize,
    #[clap(long, default_value_t = 32)]
    fragment_k: usize,
    #[clap(long, default_value_t = 80)]
    fragment_n: usize,
    #[clap(long, default_value_t = 0)]
    fragment_size: usize,

    #[clap(long)]
    expected_churn_interval: Option<u64>,

    #[clap(long)]
    kademlia: bool,
    #[clap(long)]
    slow: bool,
    #[clap(long, default_value_t = 1)]
    repeat: usize,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE)
        .init();
    let cli = Cli::parse();
    assert!(cli.fragment_k <= cli.fragment_n);
    assert!(cli.chunk_k <= cli.chunk_n);

    if cli.bootstrap_service {
        let app = start_base(&cli, "service").await;
        ctrl_c().await.unwrap();
        drop(app.handle);
        app.event_loop.await.unwrap();
        return;
    }
    let mut config = AppConfig {
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
        membership_interval: Duration::from_secs(30),
        gossip_interval: Duration::from_secs(12),
        invite_interval: Duration::from_secs(30),
    };
    if cli.expected_churn_interval.is_none() {
        config.membership_interval = Duration::from_secs(86400);
        config.gossip_interval = Duration::from_secs(86400);
    }

    let init_base = |base: StartBase, delay_range: Range<Duration>, register_after: Duration| {
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
        eprintln!("protocol,chunk_k,chunk_n,fragment_k,fragment_n,op,latency");

        for _ in 0..cli.repeat {
            let base = init_base(
                start_base(&cli, "put").await,
                Duration::ZERO..Duration::from_millis(1),
                Duration::ZERO,
            )
            .await
            .unwrap();
            let mut data = vec![0; config.fragment_size * config.fragment_k * config.chunk_k];
            thread_rng().fill_bytes(&mut data);
            let mut chunks = Vec::new();
            let mut kademlia_keys = Vec::new();

            let put_start = Instant::now();
            if cli.kademlia {
                let mut put_ids = std::collections::HashSet::new();
                async {
                    let mut fragments = Vec::new();
                    for (i, fragment) in data.chunks_exact(config.fragment_size).enumerate() {
                        let fragment = fragment.to_vec();
                        let key = Code::Sha2_256.digest(&fragment);
                        kademlia_keys.push(key);
                        if i >= 1 {
                            fragments.push((key, fragment));
                            continue;
                        }
                        let put_id = base
                            .handle
                            .ingress_wait(move |swarm| {
                                let record = Record::new(key, fragment);
                                let put_id = swarm
                                    .behaviour_mut()
                                    .kad
                                    .put_record(
                                        record,
                                        libp2p::kad::Quorum::N(3.try_into().unwrap()),
                                    )
                                    .unwrap();
                                swarm.behaviour_mut().kad.remove_record(&key.into());
                                put_id
                            })
                            .await;
                        put_ids.insert(put_id);
                    }
                    base.handle
                        .subscribe(move |event, swarm| match event.as_ref().unwrap() {
                            SwarmEvent::Behaviour(BaseEvent::Kad(
                                // TODO check result
                                KademliaEvent::OutboundQueryProgressed { id, result: _, .. },
                            )) => {
                                if put_ids.remove(id) {
                                    tracing::debug!("put fragment {id:?}");
                                    if let Some((key, fragment)) = fragments.pop() {
                                        let record = Record::new(key, fragment);
                                        let put_id = swarm
                                            .behaviour_mut()
                                            .kad
                                            .put_record(
                                                record,
                                                libp2p::kad::Quorum::N(3.try_into().unwrap()),
                                            )
                                            .unwrap();
                                        swarm.behaviour_mut().kad.remove_record(&key.into());
                                        put_ids.insert(put_id);
                                    }
                                }
                                if put_ids.is_empty() {
                                    // if *id == put_id {
                                    ControlFlow::Break(())
                                } else {
                                    ControlFlow::Continue(())
                                }
                            }
                            _ => ControlFlow::Continue(()),
                        })
                        .await;
                    // }
                }
                .instrument(info_span!("put"))
                .await
            } else {
                let mut app = App::new(base.handle, base.keypair, base.addr, config.clone());
                let control = app.control();
                let _app_loop = spawn(async move {
                    app.serve().await;
                    app
                });
                async {
                    let mut put_chunks = control.put(data);
                    while let Some((chunk_index, chunk_hash, members)) = put_chunks.recv().await {
                        tracing::info!("put chunk {chunk_hash:02x?}");
                        chunks.push((chunk_index, chunk_hash, members));
                    }
                }
                .instrument(info_span!("put"))
                .await;
                control.close();
                // let app = app_loop.await.unwrap();
                // drop(app.base);
            }
            let put_latency = Instant::now() - put_start;

            if !cli.kademlia {
                sleep(Duration::from_secs(5)).await; // so putter have sent out all fragments
            }
            let base = init_base(
                start_base(&cli, "get").await,
                Duration::ZERO..Duration::from_millis(1),
                Duration::ZERO,
            )
            .await
            .unwrap();

            let get_start = Instant::now();
            if cli.kademlia {
                async {
                    for key in kademlia_keys {
                        let get_id = base
                            .handle
                            .ingress_wait(move |swarm| {
                                swarm.behaviour_mut().kad.get_record(key.into())
                            })
                            .await;
                        let _fragment =
                            base.handle
                                .subscribe(move |event, swarm| match event.as_ref().unwrap() {
                                    SwarmEvent::Behaviour(BaseEvent::Kad(
                                        KademliaEvent::OutboundQueryProgressed {
                                            id,
                                            result:
                                                QueryResult::GetRecord(Ok(GetRecordOk::FoundRecord(
                                                    result,
                                                ))),
                                            ..
                                        },
                                    )) => {
                                        // put_ids.remove(id);
                                        // if put_ids.is_empty() {
                                        if *id == get_id {
                                            if let Some(mut query) =
                                                swarm.behaviour_mut().kad.query_mut(id)
                                            {
                                                query.finish()
                                            }
                                            ControlFlow::Break(result.record.value.clone())
                                        } else {
                                            ControlFlow::Continue(())
                                        }
                                    }
                                    _ => ControlFlow::Continue(()),
                                })
                                .await;
                    }
                }
                .instrument(info_span!("get"))
                .await
            } else {
                async {
                    let mut app = App::new(base.handle, base.keypair, base.addr, config.clone());
                    let control = app.control();
                    let _app_loop = spawn(async move {
                        app.serve().await;
                        app
                    });
                    let mut tasks = Vec::new();
                    for (chunk_index, chunk_hash, members) in
                        chunks.into_iter().take(config.chunk_k + 1)
                    {
                        let mut get_fragments = if cli.slow {
                            control.get(&chunk_hash)
                        } else {
                            control.get_with_members(&chunk_hash, members)
                        };
                        let mut decoder = WirehairDecoder::new(
                            (config.fragment_size * config.fragment_k) as _,
                            config.fragment_size as _,
                        );
                        let task = spawn(async move {
                            while let Some((id, fragment)) = get_fragments.recv().await {
                                tracing::debug!("get fragment {chunk_index} {id}");
                                let recovered = decoder.decode(id, &fragment).unwrap();
                                if recovered {
                                    break;
                                }
                            }
                            let mut chunk = vec![0; decoder.message_bytes as _];
                            decoder.recover(&mut chunk).unwrap();
                            tracing::info!("get chunk {chunk_index}");
                            (chunk_index, chunk)
                        });
                        tasks.push(task);
                    }
                    let mut decoder = WirehairDecoder::new(
                        (config.fragment_size * config.fragment_k * config.chunk_k) as _,
                        (config.fragment_size * config.fragment_k) as _,
                    );
                    for task in tasks {
                        let (chunk_index, chunk) = task.await.unwrap();
                        if decoder.decode(chunk_index, &chunk).unwrap() {
                            break;
                        }
                    }
                    let mut buffer = vec![0; decoder.message_bytes as _];
                    decoder.recover(&mut buffer).unwrap();
                }
                .instrument(info_span!("get"))
                .await;
            }
            let get_latency = Instant::now() - get_start;

            for (op, latency) in [("put", put_latency), ("get", get_latency)] {
                eprintln!(
                    "{},{},{},{},{},{},{}",
                    if cli.kademlia { "kademlia" } else { "entropy" },
                    config.chunk_k,
                    config.chunk_n,
                    config.fragment_k,
                    config.fragment_n,
                    op,
                    latency.as_secs_f32()
                );
            }
        }
        return;
    }

    let mut tasks = Vec::new();
    for i in 0..cli.n {
        tasks.push(init_base(
            start_base(&cli, format!("normal-{i}")).await,
            // wait for the farest peers
            // Duration::ZERO..Duration::from_millis(20 * 1000),
            Duration::from_millis(2 * 1000)..Duration::from_millis(10 * 1000),
            // up to 20s random delay diff + up to 40s bootstrap latency
            // Duration::from_millis(80 * 1000),
            Duration::from_millis(25 * 1000),
        ));
    }

    let mut bases = Vec::new();
    for task in tasks {
        bases.push(task.await.unwrap());
    }
    tracing::info!("READY");

    struct Instance {
        base_loop: JoinHandle<Swarm<Base>>,
        base_monitor: JoinHandle<()>,
        app_control: AppControl,
        app_loop: JoinHandle<()>,
        bandwidth: Arc<BandwidthSinks>,
    }
    let mut instances = Vec::new();
    let (mut inbound_zero, mut outbound_zero) = (0, 0);
    const REFRESH_INTERVAL: Duration = Duration::from_secs(30);
    for base in bases {
        let base_monitor = if cli.expected_churn_interval.is_some() {
            base.handle.serve_kad_refresh(REFRESH_INTERVAL)
        } else {
            // disabled
            spawn(async move {})
        };
        let mut app = App::new(base.handle, base.keypair, base.addr, config.clone());
        let app_control = app.control();
        let app_loop = spawn(async move { app.serve().await });

        inbound_zero += base.bandwidth.total_inbound();
        outbound_zero += base.bandwidth.total_outbound();

        instances.push(Instance {
            base_loop: base.event_loop,
            base_monitor,
            app_control,
            app_loop,
            bandwidth: base.bandwidth,
        });
    }
    let (mut inbound, mut outbound) = (0, 0);
    let mut replace_count = 0;

    loop {
        let mut churn_delay =
            Box::pin(sleep(if let Some(interval) = cli.expected_churn_interval {
                Duration::from_secs_f64(
                    Poisson::new(interval as f64)
                        .unwrap()
                        .sample(&mut thread_rng()),
                )
            } else {
                Duration::from_secs(86400)
            }));
        select! {
            result = ctrl_c() => {
                result.unwrap();
                break;
            }
            _ = churn_delay => {
                async {
                    let index = thread_rng().gen_range(0..cli.n);
                    let instance = instances.swap_remove(index);
                    instance.base_monitor.abort();
                    instance.app_control.close();
                    instance.app_loop.await.unwrap();
                    instance.base_loop.await.unwrap();
                    inbound += instance.bandwidth.total_inbound();
                    outbound += instance.bandwidth.total_outbound();

                    let base = start_base(&cli, format!("replace-{replace_count}")).await;
                    replace_count += 1;
                    let base_monitor = base.handle.serve_kad_refresh(REFRESH_INTERVAL);
                    let mut app = App::new(base.handle, base.keypair, base.addr, config.clone());
                    let app_control = app.control();
                    let app_loop = spawn(async move { app.serve().await });
                    instances.push(Instance {
                        base_loop: base.event_loop,
                        base_monitor,
                        app_control,
                        app_loop,
                        bandwidth: base.bandwidth,
                    });
                }
                .instrument(info_span!("churn"))
                .await;

                churn_delay = Box::pin(sleep(Duration::from_secs_f64(
                    Poisson::new(cli.expected_churn_interval.unwrap() as f64)
                        .unwrap()
                        .sample(&mut thread_rng()),
                )));
                tracing::trace!(?churn_delay); // to disable false positive unused assignment
            }
        }
    }
    for instance in instances {
        inbound += instance.bandwidth.total_inbound();
        outbound += instance.bandwidth.total_outbound();
    }
    fs::write(
        "bandwidth.txt",
        format!("{},{}\n", inbound - inbound_zero, outbound - outbound_zero),
    )
    .await
    .unwrap();
}

struct StartBase {
    event_loop: JoinHandle<Swarm<Base>>,
    handle: BaseHandle,
    keypair: Keypair,
    addr: Multiaddr,
    bandwidth: Arc<BandwidthSinks>,
}

async fn start_base(cli: &Cli, name: impl ToString) -> StartBase {
    let id_keys = Keypair::generate_ed25519();
    let transport = tcp::tokio::Transport::new(tcp::Config::default().nodelay(true))
        .upgrade(V1)
        .authenticate(libp2p::noise::NoiseAuthenticated::xx(&id_keys).unwrap())
        .multiplex(libp2p::yamux::YamuxConfig::default())
        .boxed();
    let (transport, bandwidth) = transport.with_bandwidth_logging();
    let (event_loop, handle) = Base::run(
        name,
        transport,
        &id_keys,
        cli.expected_churn_interval.is_some(),
    );
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
        bandwidth,
    }
}
