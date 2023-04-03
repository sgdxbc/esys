use std::collections::{BTreeMap, HashMap};

use rand::{seq::IteratorRandom, thread_rng, Rng};
use rand_distr::{Distribution, Poisson};

struct Config {
    churn_rate: f32,  // nodes leaving in one year / node count
    faulty_rate: f32, // faulty node count / node count
    node_count: u32,
    duration: u32, // years
    object_count: u32,
    chunk_n: u32,
    chunk_k: u32,
    fragment_n: u32,
    fragment_k: u32,
    allow_data_lost: bool,
    committee_check_interval_sec: u32,
}

#[derive(Debug)]
enum Event {
    Churn,
    RefillCommittee(ObjectId, ChunkId),
    End,
}

struct System {
    config: Config,
    events: BTreeMap<(Instant, u32), Event>,
    now: u32,

    nodes: HashMap<NodeId, Node>,
    objects: Vec<Object>,
    next_node: NodeId,
    next_event: u32,

    stats: Stats,
}

#[derive(Default)]
struct Node {
    faulty: bool,
    // each node should be responsible for at most one fragment per chunk
    fragments: HashMap<(ObjectId, ChunkId), FragmentId>,
}

#[derive(Default, Clone)]
struct Object {
    // cache of `len(_ for chunk in chunks if chunk is still alive)`
    alive_count: u32,
    chunks: Vec<Chunk>,
}

// `Committee` at the same time
#[derive(Default, Clone)]
struct Chunk {
    // [{reverse map fragment => node}]
    // this the fragments that "seems to exist" i.e. faulty nodes are included
    // committee use this size to conduct refilling
    fragments: HashMap<FragmentId, NodeId>,
    // cache of `len(_ for fragment in fragments if fragment.node is not faulty)`
    // simulation use this count to determine chunk liveness
    alive_count: u32,
    next_fragment: FragmentId,
}

type Instant = u32;
type NodeId = u32;
type ObjectId = u32;
type ChunkId = u32;
type FragmentId = u32;

#[derive(Debug, Default)]
struct Stats {
    churn: u32,
    data_lost: u32,
}

impl System {
    fn new(config: Config, mut rng: impl Rng) -> Self {
        let mut system = Self {
            events: Default::default(),
            now: 0,
            nodes: Default::default(),
            objects: vec![Default::default(); config.object_count as _],
            next_node: 0,
            next_event: 0,
            stats: Default::default(),
            config,
        };
        for _ in 0..system.config.node_count {
            system.add_node(rng.gen_bool(system.config.faulty_rate as _));
        }
        for id in 0..system.config.object_count {
            system.add_object(id, &mut rng);
        }
        system.add_churn_event(&mut rng);
        system
    }

    fn add_event(&mut self, after: u32, event: Event) {
        let at = self.now + after;
        let id = self.next_event;
        self.next_event += 1;
        self.events.insert((at, id), event);
    }

    fn add_node(&mut self, faulty: bool) {
        let id = self.next_node;
        self.next_node += 1;
        let node = Node {
            faulty,
            ..Default::default()
        };
        self.nodes.insert(id, node);
    }

    fn remove_node(&mut self, exit_id: NodeId, mut rng: impl Rng) {
        let exit_node = self.nodes.remove(&exit_id).unwrap();
        assert!(!exit_node.faulty);
        for ((object_id, chunk_id), fragment_id) in exit_node.fragments {
            let node_id = self.remove_fragment(object_id, chunk_id, fragment_id, &mut rng);
            assert_eq!(node_id, exit_id);
        }
    }

    fn add_object(&mut self, id: u32, mut rng: impl Rng) {
        self.objects[id as usize]
            .chunks
            .resize(self.config.chunk_n as _, Default::default());
        for chunk_id in 0..self.config.chunk_n {
            self.fill_chunk(id, chunk_id, &mut rng);
            if self.objects[id as usize].chunks[chunk_id as usize].alive_count
                >= self.config.fragment_k
            {
                self.objects[id as usize].alive_count += 1;
            }
        }
    }
    // we don't simulate remove object :)

    fn fill_chunk(&mut self, object_id: u32, chunk_id: u32, mut rng: impl Rng) {
        // when certain fragment is "skipped" by reason described in `add_fragment`, this filling may not be "instant",
        // i.e. it should take several "committee check round" to finish
        // TODO consider simulate this duration
        while (self.objects[object_id as usize].chunks[chunk_id as usize]
            .fragments
            .len() as u32)
            < self.config.fragment_n
        {
            self.add_fragment(object_id, chunk_id, &mut rng);
        }
        if self.objects[object_id as usize].chunks[chunk_id as usize].alive_count
            < self.config.fragment_k
        {
            // this should not happen at all...at least for genuine entropy
            todo!()
        }
    }

    fn add_fragment(&mut self, object_id: u32, chunk_id: u32, mut rng: impl Rng) {
        let chunk = &mut self.objects[object_id as usize].chunks[chunk_id as usize];
        let fragment_id = chunk.next_fragment;
        chunk.next_fragment += 1;

        // simulate random fragment hash + closest distance with `.choose()`
        // it's unlikely for a node to have double (or even more) responsibility in the same committee
        // but if that actually happen, the honest behavior is to keep unresponsive to the higher fragment index
        // so the committee will skip it soon
        // in this way no more than one fragment will be (trustfully) stored in the same failure domain

        let (node_id, node) = self.nodes.iter_mut().choose(&mut rng).unwrap();
        // this is a committee consensus, so even it's duplicated responsibility of faulty node, the fragment can be
        // skipped successfully
        if node.fragments.contains_key(&(object_id, chunk_id)) {
            return;
        }
        node.fragments.insert((object_id, chunk_id), fragment_id);
        chunk.fragments.insert(fragment_id, *node_id);
        if !node.faulty {
            chunk.alive_count += 1;
        }
    }

    fn remove_fragment(
        &mut self,
        object_id: ObjectId,
        chunk_id: ChunkId,
        fragment_id: FragmentId,
        mut rng: impl Rng,
    ) -> NodeId {
        let object = &mut self.objects[object_id as usize];
        let chunk = &mut object.chunks[chunk_id as usize];
        let prev_count = chunk.alive_count;
        let node_id = chunk.fragments.remove(&fragment_id).unwrap();
        // assert!(!self.nodes[&node_id].faulty);
        chunk.alive_count -= 1;

        if prev_count == self.config.fragment_k {
            let prev_count = object.alive_count;
            object.alive_count -= 1;
            if prev_count == self.config.chunk_k {
                assert!(self.config.allow_data_lost);
                self.stats.data_lost += 1;
            }
        }

        // when chunk is not recoverable, refilling is not possible
        if prev_count as u32 > self.config.chunk_k {
            self.add_event(
                // in the worst case the peer fails immediately after sending heartbeat, which is immediately after
                // the committee start a new checking interval
                rng.gen_range(1..self.config.committee_check_interval_sec * 2),
                Event::RefillCommittee(object_id, chunk_id),
            );
        }

        node_id
    }

    fn add_churn_event(&mut self, mut rng: impl Rng) {
        let expect_interval =
            (86400. * 365.) / (self.config.churn_rate * self.config.node_count as f32);
        let after = Poisson::new(expect_interval).unwrap().sample(&mut rng) as u32;
        self.add_event(after, Event::Churn);
    }

    fn on_churn(&mut self, mut rng: impl Rng) {
        self.stats.churn += 1;

        let (exit_id, exit_node) = self.nodes.iter().choose(&mut rng).unwrap();
        // faulty node never leave
        // because faulty node never store anything, so does not "discard nothing" here should not make the attack even
        // weaker
        // if faulty node always live, it can stay in the committee until get kicked out, and this should make the
        // attack stronger
        if !exit_node.faulty {
            self.remove_node(*exit_id, &mut rng);
            self.add_node(false); // prevent increase number of faulty
        }

        self.add_churn_event(&mut rng);
    }

    fn on_refill_committee(&mut self, object_id: ObjectId, chunk_id: ChunkId, rng: impl Rng) {
        if (self.objects[object_id as usize].chunks[chunk_id as usize]
            .fragments
            .len() as u32)
            < self.config.fragment_k
        {
            unreachable!() // for now
        }
        self.fill_chunk(object_id, chunk_id, rng);
    }

    fn run(&mut self, mut rng: impl Rng) {
        self.add_event(self.config.duration * 86400 * 365, Event::End);
        loop {
            let event;
            ((self.now, _), event) = self.events.pop_first().unwrap();
            println!("{event:?}");
            use Event::*;
            match event {
                Churn => self.on_churn(&mut rng),
                RefillCommittee(object_id, chunk_id) => {
                    self.on_refill_committee(object_id, chunk_id, &mut rng)
                }
                End => break,
            }
        }
    }
}

fn main() {
    let config = Config {
        churn_rate: 1.,
        node_count: 1000,
        duration: 1,
        faulty_rate: 0.,
        object_count: 1,
        chunk_n: 1,
        chunk_k: 1,
        fragment_n: 100,
        fragment_k: 80,
        allow_data_lost: false,
        committee_check_interval_sec: 12 * 60 * 60,
    };
    let mut system = System::new(config, thread_rng());
    system.run(thread_rng());
    println!("{:?}", system.stats);
}
