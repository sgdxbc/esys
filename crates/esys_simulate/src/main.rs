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
}

enum Event {
    Churn,
}

struct System {
    config: Config,
    events: BTreeMap<(Instant, u32), Event>,
    now: u32,

    nodes: HashMap<NodeId, Node>,
    // [for object [for chunk {reverse map fragment => node}]]
    objects: Vec<Vec<HashMap<FragmentId, NodeId>>>,
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

type Instant = u32;
type NodeId = u32;
type ObjectId = u32;
type ChunkId = u32;
type FragmentId = u32;

#[derive(Debug, Default)]
struct Stats {
    churn: u32,
}

impl System {
    fn new(config: Config, mut rng: impl Rng) -> Self {
        let mut system = Self {
            events: Default::default(),
            now: 0,
            nodes: Default::default(),
            objects: vec![vec![Default::default(); config.chunk_n as _]; config.object_count as _],
            next_node: 0,
            next_event: 0,
            stats: Default::default(),
            config,
        };
        for _ in 0..system.config.node_count {
            system.add_node(&mut rng);
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

    fn add_node(&mut self, mut rng: impl Rng) {
        let id = self.next_node;
        self.next_node += 1;
        let node = Node {
            faulty: rng.gen_bool(self.config.faulty_rate as _),
            ..Default::default()
        };
        self.nodes.insert(id, node);
    }

    fn add_object(&mut self, id: u32, mut rng: impl Rng) {
        for chunk_id in 0..self.config.chunk_n {
            for fragment_id in 0..self.config.fragment_n {
                self.add_fragment(id, chunk_id, fragment_id, &mut rng);
            }
        }
    }

    fn add_fragment(&mut self, object_id: u32, chunk_id: u32, fragment_id: u32, mut rng: impl Rng) {
        // simulate random fragment hash + closest distance with `.choose()`
        // it's unlikely for a node to have double (or even more) responsibility in the same committee
        // but if that actually happen, the honest behavior is to keep unresponsive to the higher fragment index
        // so the committee will skip it soon
        // in this way no more than one fragment will be (trustfully) stored in the same failure domain

        let (node_id, node) = self.nodes.iter_mut().choose(&mut rng).unwrap();
        if node.faulty || node.fragments.contains_key(&(object_id, chunk_id)) {
            return;
        }
        node.fragments.insert((object_id, chunk_id), fragment_id);
        self.objects[object_id as usize][chunk_id as usize].insert(fragment_id, *node_id);
    }

    fn add_churn_event(&mut self, mut rng: impl Rng) {
        let expect_interval =
            (86400. * 365.) / (self.config.churn_rate * self.config.node_count as f32);
        let after = Poisson::new(expect_interval).unwrap().sample(&mut rng) as u32;
        self.add_event(after, Event::Churn);
    }

    fn run(&mut self, mut rng: impl Rng) {
        while self.now < self.config.duration * 86400 * 365 {
            let event;
            ((self.now, _), event) = self.events.pop_first().unwrap();
            use Event::*;
            match event {
                Churn => {
                    self.stats.churn += 1;
                    //
                    self.add_churn_event(&mut rng);
                }
            }
        }
    }
}

fn main() {
    let config = Config {
        churn_rate: 1.,
        node_count: 1000,
        duration: 10,
        faulty_rate: 0.1,
        object_count: 1,
        chunk_n: 1,
        chunk_k: 1,
        fragment_n: 1,
        fragment_k: 1,
    };
    let mut system = System::new(config, thread_rng());
    system.run(thread_rng());
    println!("{:?}", system.stats);
}
