// The things we don't simulate
//
// There's no network partition (or significant message latency that could cause similar effect). So committee members
// always have consistent view and behavior. The probability of data lost may or may not increase in a more asynchrony
// setup, but it's too hard for me to model that.
//
// There's no latency between committee member exits and committee finishes to find new member. Actually, just treat the
// `Churn` event as "the event where committee reach concensus on the member has exited". The member node actually exit
// (probably short) before that. Here we have an assumption that the committee realize member exiting in bounded time.
// This should be true in our network model.
//
// One consequence of the two above is the "unstability" brought by VRF is not simulated. In reality, VRF may choose
// multiple nodes for the same fragment index, may choose same node for multiple fragment indexes, and may choose no
// node for certain fragment index. Because there's no latency and inconsistency issue for committee to resolve these
// accidents, simulating by selecting exact number of committee members whenever necessary should give the equivalent
// result.
//
// Methodology for simulating targeted attack
//
// Configuration predefine a fixed number of chunks/groups to be targeted attack. The attacked groups are statically
// selected before simulation start.
//
// These chunks are not counted as alive for all times. This effectively simulates the groups are under attack for all
// times, which is the upper bound of the effect of the attacking. In another word, if there's data lost happen at a
// certain time, we are simulating the case where the lucky attacker happens to perform attack at that time point.
//
// The simulation also monitors the total number of targeted nodes. The upper bound of number of targeted nodes is
// `targeted_count * fragment_n`, but the actually targeted nodes may be less than that because of overlapping groups
// or the targeted group is already non-recoverable so it cannot (try to) maintain `fragment_n` group members any more.
// When it's probably necessary to perform attacking i.e. there's data lost happening, the number of current targeted
// nodes is recorded, and the maximum of these recorded targeted node count is considered as the peak attacking
// effort/power and will be plotted.

// use std::collections::{BTreeMap, HashMap, HashSet};
use rustc_hash::{FxHashMap as HashMap, FxHashSet as HashSet};
use std::collections::BTreeMap;

use rand::{
    seq::{IteratorRandom, SliceRandom},
    thread_rng, Rng,
};
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
    targeted_count: u32,
}

#[derive(Debug)]
enum Event {
    Churn,
    IncreaseWatermark(FragmentId), // add (object, chunk) if not all chunk spawn at/close to time zero
    End,
}

struct System {
    config: Config,
    events: BTreeMap<(Instant, u32), Event>,
    now: u32,

    nodes: HashMap<NodeId, Node>,
    nodes_cache: Vec<NodeId>, // speed up node selection
    targeted_nodes: HashSet<NodeId>,
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
    // cache of `len(_ for chunk in chunks if chunk is still alive and not targeted)`
    alive_count: u32,
    chunks: Vec<Chunk>,
}

// `Group` at the same time
#[derive(Default, Clone)]
struct Chunk {
    // [{reverse map fragment => node}]
    fragments: HashMap<FragmentId, NodeId>,
    // cache of `len(_ for fragment in fragments if fragment.node is alive and not faulty)`
    // simulation use this count to determine chunk liveness
    alive_count: u32,
    // lowest fragment that has not yet (tried to) be included in the group
    next_fragment: FragmentId,
    targeted: bool,
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
    targeted: u32,
}

impl System {
    fn new(config: Config, mut rng: impl Rng) -> Self {
        let mut system = Self {
            events: Default::default(),
            now: 0,
            nodes: Default::default(),
            nodes_cache: Default::default(),
            targeted_nodes: Default::default(),
            objects: Default::default(),
            next_node: 0,
            next_event: 0,
            stats: Default::default(),
            config,
        };

        for _ in 0..system.config.node_count {
            system.add_node(rng.gen_bool(system.config.faulty_rate as _));
        }
        for _ in 0..system.config.object_count {
            system.add_object(&mut rng);
        }

        let targeted_groups = (0..system.config.object_count)
            .flat_map(|object_id| {
                (0..system.config.chunk_n).map(move |chunk_id| (object_id, chunk_id))
            })
            .choose_multiple(&mut rng, system.config.targeted_count as _);
        for &(object_id, chunk_id) in &targeted_groups {
            let object = &mut system.objects[object_id as usize];
            let chunk = &mut object.chunks[chunk_id as usize];
            chunk.targeted = true;
            system.targeted_nodes.extend(chunk.fragments.values());
        }
        system
            .targeted_nodes
            .retain(|node_id| !system.nodes[node_id].faulty);
        // make sure `targeted_nodes` is completely initialized before it might be recorded into stats
        for (object_id, chunk_id) in targeted_groups {
            system.lose_chunk(object_id, chunk_id);
        }

        system.add_churn_event(&mut rng);
        system.insert_event(
            system.config.increase_watermark_interval_sec(),
            Event::IncreaseWatermark(0),
        );
        system
    }

    fn insert_event(&mut self, after: u32, event: Event) {
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
        self.nodes_cache.push(id);
    }

    fn remove_node(&mut self, exit_id: NodeId, mut rng: impl Rng) {
        let exit_node = self.nodes.remove(&exit_id).unwrap();
        let index = self.nodes_cache.binary_search(&exit_id).unwrap();
        self.nodes_cache.remove(index); // any better idea?

        assert!(!exit_node.faulty);
        self.targeted_nodes.remove(&exit_id);
        for ((object_id, chunk_id), fragment_id) in exit_node.fragments {
            let node_id = self.remove_fragment(object_id, chunk_id, fragment_id);
            assert_eq!(node_id, exit_id);
            // refill for targeted but recoverable chunks
            if self.chunk_recoverable(object_id, chunk_id) {
                self.fill_chunk(object_id, chunk_id, &mut rng);
            }
        }
    }

    fn add_object(&mut self, mut rng: impl Rng) {
        let object_id = self.objects.len() as ObjectId;
        self.objects.push(Object {
            alive_count: 0,
            chunks: vec![Default::default(); self.config.chunk_n as _],
        });
        for chunk_id in 0..self.config.chunk_n {
            self.fill_chunk(object_id, chunk_id, &mut rng);
            if self.chunk_alive(object_id, chunk_id) {
                self.objects[object_id as usize].alive_count += 1;
            }
        }
        // the object lost immediately after putting into system
        if self.objects[object_id as usize].alive_count < self.config.chunk_k {
            assert!(self.config.allow_data_lost);
            self.stats.data_lost += 1;
        }
    }
    // we don't simulate remove object :)

    fn chunk(&self, object_id: ObjectId, chunk_id: ChunkId) -> &Chunk {
        &self.objects[object_id as usize].chunks[chunk_id as usize]
    }

    fn chunk_mut(&mut self, object_id: ObjectId, chunk_id: ChunkId) -> &mut Chunk {
        &mut self.objects[object_id as usize].chunks[chunk_id as usize]
    }

    fn chunk_alive(&self, object_id: ObjectId, chunk_id: ChunkId) -> bool {
        !self.chunk(object_id, chunk_id).targeted && self.chunk_recoverable(object_id, chunk_id)
    }

    fn chunk_recoverable(&self, object_id: ObjectId, chunk_id: ChunkId) -> bool {
        self.chunk(object_id, chunk_id).alive_count >= self.config.fragment_k
    }

    fn fill_chunk(&mut self, object_id: ObjectId, chunk_id: ChunkId, mut rng: impl Rng) {
        while (self.chunk(object_id, chunk_id).fragments.len() as u32) < self.config.fragment_n {
            self.add_fragment(object_id, chunk_id, &mut rng);
        }
    }

    fn lose_chunk(&mut self, object_id: ObjectId, chunk_id: ChunkId) {
        assert!(!self.chunk_alive(object_id, chunk_id));
        let object = &mut self.objects[object_id as usize];
        let prev_count = object.alive_count;
        object.alive_count -= 1;
        if prev_count == self.config.chunk_k {
            assert!(self.config.allow_data_lost);
            self.stats.data_lost += 1;
            self.stats.targeted = u32::max(self.stats.targeted, self.targeted_nodes.len() as _);
        }
    }

    fn add_fragment(&mut self, object_id: u32, chunk_id: u32, mut rng: impl Rng) {
        let chunk = self.chunk_mut(object_id, chunk_id);
        let fragment_id = chunk.next_fragment;
        chunk.next_fragment += 1;

        // simulate random fragment hash + closest distance with `.choose()`
        // let (node_id, node) = self.nodes.iter_mut().choose(&mut rng).unwrap();
        let node_id = self.nodes_cache.choose(&mut rng).unwrap();
        let node = self.nodes.get_mut(node_id).unwrap();

        // it's unlikely for a node to have double (or even more) responsibility in the same committee
        // but if that actually happen, the honest behavior is to keep unresponsive to the higher fragment index
        // so the committee will skip it soon
        // in this way no more than one fragment will be (trustfully) stored in the same failure domain
        // this is a committee consensus, so even it's duplicated responsibility of faulty node, the fragment can be
        // skipped successfully
        // TODO not sure whether it is still true for current weaker consensus
        if node.fragments.contains_key(&(object_id, chunk_id)) {
            return;
        }
        node.fragments.insert((object_id, chunk_id), fragment_id);
        let node_id = *node_id;
        let faulty = node.faulty;
        let chunk = self.chunk_mut(object_id, chunk_id);
        chunk.fragments.insert(fragment_id, node_id);
        if !faulty {
            chunk.alive_count += 1;
        }
        if chunk.targeted {
            self.targeted_nodes.insert(node_id);
        }
    }

    fn remove_fragment(
        &mut self,
        object_id: ObjectId,
        chunk_id: ChunkId,
        fragment_id: FragmentId,
    ) -> NodeId {
        let node_id = self
            .chunk_mut(object_id, chunk_id)
            .fragments
            .remove(&fragment_id)
            .unwrap();

        // if the node is still in `nodes`, this removing is caused by watermark
        let lose_fragment = if let Some(node) = self.nodes.get_mut(&node_id) {
            let removed_id = node.fragments.remove(&(object_id, chunk_id));
            assert_eq!(removed_id, Some(fragment_id));
            !node.faulty
        } else {
            // otherwise the removing is caused by removing node, which only happens to honest nodes
            true
        };
        if lose_fragment {
            let prev_alive = self.chunk_alive(object_id, chunk_id);
            self.chunk_mut(object_id, chunk_id).alive_count -= 1;
            if prev_alive && !self.chunk_alive(object_id, chunk_id) {
                self.lose_chunk(object_id, chunk_id);
            }
        }

        node_id
    }

    fn add_churn_event(&mut self, mut rng: impl Rng) {
        let expect_interval =
            (86400. * 365.) / (self.config.churn_rate * self.config.node_count as f32);
        let after = Poisson::new(expect_interval).unwrap().sample(&mut rng) as u32;
        self.insert_event(after, Event::Churn);
    }

    fn on_churn(&mut self, mut rng: impl Rng) {
        self.stats.churn += 1;

        // let (exit_id, exit_node) = self.nodes.iter().choose(&mut rng).unwrap();
        let exit_id = self.nodes_cache.choose(&mut rng).unwrap();
        let exit_node = &self.nodes[exit_id];
        // faulty node never leave
        // because faulty node never store anything, so does not "discard nothing" here should not make the attack even
        // weaker
        // if faulty node always live, it can stay in the committee until get kicked out, and this should make the
        // attack stronger
        if !exit_node.faulty {
            self.remove_node(*exit_id, &mut rng);
            // the new node is added after all involved committee find their new members
            // seems reasonable and not increasing durability
            self.add_node(false); // prevent increase number of faulty
        }

        self.add_churn_event(&mut rng);
    }

    fn on_increase_watermark(&mut self, fragment_id: FragmentId, mut rng: impl Rng) {
        let mut evictions = Vec::new();
        for (object_id, object) in self.objects.iter_mut().enumerate() {
            for (chunk_id, chunk) in object.chunks.iter_mut().enumerate() {
                if chunk.fragments.contains_key(&fragment_id) {
                    evictions.push((object_id as ObjectId, chunk_id as ChunkId));
                }
            }
        }
        for (object_id, chunk_id) in evictions {
            // TODO remove targeted node
            self.remove_fragment(object_id, chunk_id, fragment_id);
            if self.chunk_alive(object_id, chunk_id) {
                self.fill_chunk(object_id, chunk_id, &mut rng);
            }
        }
        self.insert_event(
            self.config.increase_watermark_interval_sec(),
            Event::IncreaseWatermark(fragment_id + 1),
        );
    }

    fn on_end(&mut self) {}

    fn run(&mut self, mut rng: impl Rng) {
        self.insert_event(self.config.duration * 86400 * 365, Event::End);
        loop {
            let event;
            ((self.now, _), event) = self.events.pop_first().unwrap();
            // println!("{event:?}");
            use Event::*;
            match event {
                Churn => self.on_churn(&mut rng),
                IncreaseWatermark(fragment_id) => self.on_increase_watermark(fragment_id, &mut rng),
                End => {
                    self.on_end();
                    break;
                }
            }
        }
    }
}

impl Config {
    fn increase_watermark_interval_sec(&self) -> u32 {
        (365. * 86400. / self.churn_rate / self.fragment_n as f32) as _
    }
}

fn main() {
    let config = Config {
        churn_rate: 0.1,
        node_count: 10000,
        duration: 10,
        faulty_rate: 0.,
        object_count: 100,
        chunk_n: 100,
        chunk_k: 80,
        fragment_n: 200,
        fragment_k: 80,
        allow_data_lost: true,
        targeted_count: 200,
    };
    let mut system = System::new(config, thread_rng());
    system.run(thread_rng());
    println!("{:?}", system.stats);
}
