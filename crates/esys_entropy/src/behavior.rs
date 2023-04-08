use std::{collections::HashMap, io};

use esys_wirehair::WirehairDecoder;
use libp2p::{
    core::{
        upgrade::{read_length_prefixed, write_length_prefixed},
        ProtocolName,
    },
    futures::{AsyncRead, AsyncWrite},
    identify::Info,
    identity::Keypair,
    kad::kbucket::Key,
    multihash::{Code, Hasher, Multihash, MultihashDigest, Sha2_256},
    request_response, PeerId,
};
use prost::Message;
use rand::{rngs::StdRng, Rng, SeedableRng};
use tokio::sync::Mutex;

use crate::AppControl;

mod proto {
    include!(concat!(env!("OUT_DIR"), "/behavior.proto.rs"));
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Protocol;

impl ProtocolName for Protocol {
    fn protocol_name(&self) -> &[u8] {
        "/entropy/0.1.0".as_bytes()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct Codec;

#[async_trait::async_trait]
impl request_response::Codec for Codec {
    type Protocol = Protocol;
    type Request = proto::Request;
    type Response = proto::Response;

    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let message = read_length_prefixed(io, 64 << 10).await?;
        if message.is_empty() {
            Err(io::ErrorKind::UnexpectedEof.into())
        } else {
            match proto::Request::decode(&*message) {
                Ok(message) => Ok(message),
                Err(_) => Err(io::ErrorKind::InvalidData.into()),
            }
        }
    }

    async fn read_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let message = read_length_prefixed(io, 64 << 10).await?;
        if message.is_empty() {
            Err(io::ErrorKind::UnexpectedEof.into())
        } else {
            match proto::Response::decode(&*message) {
                Ok(message) => Ok(message),
                Err(_) => Err(io::ErrorKind::InvalidData.into()),
            }
        }
    }

    async fn write_request<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        request: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let message = request.encode_to_vec();
        assert!(message.len() < 64 << 10);
        write_length_prefixed(io, message).await
    }

    async fn write_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        response: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let message = response.encode_to_vec();
        assert!(message.len() < 64 << 10);
        write_length_prefixed(io, message).await
    }
}

pub type Behavior = request_response::Behaviour<Codec>;

#[derive(Debug)]
pub struct Control {
    chunks: HashMap<Multihash, Chunk>,
    peers: HashMap<PeerId, Info>,
    id: PeerId,
    keypair: Keypair,
}

impl Control {
    pub fn new(id: PeerId, keypair: Keypair) -> Self {
        Self {
            chunks: Default::default(),
            peers: Default::default(),
            id,
            keypair,
        }
    }
}

#[derive(Debug)]
struct Chunk {
    fragment_index: u32,
    fragment: Fragment,
    members: HashMap<PeerId, u32>,
    proofs: HashMap<u32, (PeerId, Vec<u8>)>,
}

#[derive(Debug)]
enum Fragment {
    Incomplete(Mutex<WirehairDecoder>),
    Complete(Vec<u8>),
}

impl AppControl {
    // entropy message flow
    // precondition: a group of peers that hold identical `members` view
    // invariant: every peer in `members` can be queried for one fragment
    // 1. some group member INVITE a new peer, with current `members`
    // 2. if the new peer proves itself, it broadcasts QUERY_FRAGMENT to `members`
    // 3. sufficient peers from `members` verify the new peer's proof and reply QUERY_FRAGMENT_OK with local fragment
    // 4. new peer finish recovering and generating its fragment, broadcast GOSSIP to `members`
    // 5. `members` peers insert the new peer into local `members` view, start to GOSSIP to the new peer
    //   5.1. if a member peer has not received the new peer's proof upon heard about the new peer, it sends QUERY_PROOF
    //   to new peer and insert the new peer into local `members` when receiving QUERY_PROOF_OK
    //
    // how to INVITE
    // on invite timer
    // 1. update members' liveness knowledge base on received GOSSIP
    // 2. in range `low_watermark..<highest taken fragment index>`, INVITE on every index that is not taken
    // 3. keep INVITE on increamentally even higher fragment index until sufficient fragment indexes are taken by unique
    // members
    // 4. (after all INVITE done) reset <highest taken fragment index> to the `group_size`th lowest taken fragment index
    // (above low watermark)

    pub fn gossip(&self, chunk_hash: Multihash) {
        let members = &self.entropy.chunks[&chunk_hash].members;
        let request = proto::Request {
            inner: Some(proto::request::Inner::Gossip(proto::Gossip {
                chunk_hash: chunk_hash.to_bytes(),
                members: members.keys().map(PeerId::to_bytes).collect(),
            })),
        };
        for &peer in members.keys() {
            let request = request.clone();
            self.ingress(move |swarm| {
                swarm.behaviour_mut().entropy.send_request(&peer, request);
            });
        }
    }

    pub async fn invite(&self, chunk_hash: Multihash, index: u32) {
        let chunk = &self.entropy.chunks[&chunk_hash];
        // TODO check watermarks
        if chunk.proofs.contains_key(&index) {
            return;
        }
        let fragment_hash = Self::fragment_hash(chunk_hash, index);
        // TODO try invite multiple peers
        let (peer_id, peer_addr) = self
            .query(fragment_hash)
            .await
            .expect("found peer to invite");
        if chunk.members.contains_key(&peer_id) {
            return;
        }
        let request = proto::Request {
            inner: Some(proto::request::Inner::Invite(proto::Invite {
                chunk_hash: chunk_hash.to_bytes(),
                fragment_index: index,
                members: chunk.members.keys().map(PeerId::to_bytes).collect(),
            })),
        };
        self.ingress(move |swarm| {
            swarm
                .behaviour_mut()
                .entropy
                .add_address(&peer_id, peer_addr);
            swarm
                .behaviour_mut()
                .entropy
                .send_request(&peer_id, request);
        });
    }

    // pub async fn handle_invite(&)

    pub fn handle_query_fragment(
        &self,
        peer_id: PeerId,
        message: proto::QueryFragment,
    ) -> Option<proto::QueryFragmentOk> {
        let chunk_hash = Multihash::from_bytes(&message.chunk_hash).unwrap();
        let Some(chunk) = self.entropy.chunks.get(&chunk_hash) else {
            //
            return None;
        };

        if !self.verify(chunk_hash, message.fragment_index, peer_id, &message.proof) {
            //
            return None;
        }

        let Fragment::Complete(fragment) = &chunk.fragment else {
            panic!("receive query fragment before sending gossip")
        };
        let response = proto::QueryFragmentOk {
            chunk_hash: message.chunk_hash,
            fragment_index: chunk.fragment_index,
            fragment: fragment.clone(),
        };
        Some(response)
    }

    // TODO homomorphic hashing
    fn fragment_hash(chunk_hash: Multihash, index: u32) -> Multihash {
        let mut input = chunk_hash.to_bytes();
        input.extend(&index.to_be_bytes());
        Code::Sha2_256.digest(&input)
    }

    fn accept_probablity(chunk_hash: Multihash, index: u32, peer_id: PeerId) -> f64 {
        let fragment_hash = Self::fragment_hash(chunk_hash, index);
        let distance = Key::from(fragment_hash).distance(&Key::from(peer_id));
        // TODO tune the probability distribution properly
        match distance.ilog2() {
            None => 0.95,
            Some(i) if i <= 18 => 0.9 - 0.05 * i as f64,
            _ => 0.,
        }
    }

    fn accepted(chunk_hash: Multihash, index: u32, peer_id: PeerId, proof: &[u8]) -> bool {
        let seed = {
            let mut hasher = Sha2_256::default();
            hasher.update(&proof);
            hasher.finalize().try_into().unwrap()
        };
        StdRng::from_seed(seed).gen_bool(Self::accept_probablity(chunk_hash, index, peer_id))
    }

    fn prove(&self, chunk_hash: Multihash, index: u32) -> Option<Vec<u8>> {
        let proof = {
            let mut input = chunk_hash.to_bytes();
            input.extend(&index.to_be_bytes());
            self.entropy.keypair.sign(&input).unwrap()
        };
        if Self::accepted(chunk_hash, index, self.entropy.id, &proof) {
            Some(proof)
        } else {
            None
        }
    }

    fn verify(&self, chunk_hash: Multihash, index: u32, peer_id: PeerId, proof: &[u8]) -> bool {
        let mut input = chunk_hash.to_bytes();
        input.extend(&index.to_be_bytes());
        self.entropy.peers[&peer_id]
            .public_key
            .verify(&input, proof)
            && Self::accepted(chunk_hash, index, peer_id, proof)
    }
}
