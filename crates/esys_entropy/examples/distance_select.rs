use libp2p::kad::kbucket::{Distance, KeyBytes};
use rand_distr::num_traits::Pow;

fn main() {
    let node_count = 10 * 1000;
    let target_hash = KeyBytes::new(<&[u8]>::default());
    println!("{target_hash:02x?}");
}

fn scaled_distance(node_count: usize, distance: Distance) -> i32 {
    let hash_len = 256;
    let log2_node_count = usize::BITS - node_count.leading_zeros() - 1; // assert node count not 0
                                                                        // D = 2^hash_len / node_count
    let log2_node_interval = hash_len - log2_node_count;
    distance.ilog2().unwrap() as i32 - log2_node_interval as i32
}

fn select_probability(log_distance: i32) -> f64 {
    if log_distance <= 0 {
        0.5
    } else {
        // 2 ^ log_distance to retrieve the original distance
        // 2 ^ -distance to give a exponentially decreasing probability according to distance
        // hope there's no numeric problems...
        (2f64).powf(-2f64.pow(log_distance))
    }
}
