use libp2p::kad::kbucket::KeyBytes;

fn main() {
    let target_hash = KeyBytes::new(<&[u8]>::default());
    println!("{target_hash:02x?}");
}
