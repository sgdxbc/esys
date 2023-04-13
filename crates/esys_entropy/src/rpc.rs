use std::io;

use libp2p::{
    core::{
        upgrade::{read_length_prefixed, write_length_prefixed},
        ProtocolName,
    },
    futures::{AsyncRead, AsyncWrite},
    request_response,
};
use prost::Message;

pub mod proto {
    use libp2p::{identity::PublicKey, multihash::Multihash, Multiaddr, PeerId};

    include!(concat!(env!("OUT_DIR"), "/behavior.proto.rs"));

    impl Member {
        pub fn id(&self) -> PeerId {
            PeerId::from_bytes(&self.id).unwrap()
        }

        pub fn addr(&self) -> Multiaddr {
            Multiaddr::try_from(self.addr.clone()).unwrap()
        }

        pub fn public_key(&self) -> Option<PublicKey> {
            if self.public_key.is_empty() {
                None
            } else {
                Some(PublicKey::from_protobuf_encoding(&self.public_key).unwrap())
            }
        }

        pub fn new(index: u32, public_key: &PublicKey, addr: &Multiaddr, proof: Vec<u8>) -> Self {
            Self {
                index,
                id: PeerId::from_public_key(public_key).to_bytes(),
                addr: addr.to_vec(),
                public_key: public_key.to_protobuf_encoding(),
                proof,
            }
        }

        pub fn new_trustless(index: u32, public_key: &PublicKey, addr: &Multiaddr) -> Self {
            Self {
                index,
                id: PeerId::from_public_key(public_key).to_bytes(),
                addr: addr.to_vec(),
                ..Default::default()
            }
        }
    }

    macro_rules! impl_chunk_hash {
        ($t:ty) => {
            impl $t {
                pub fn chunk_hash(&self) -> Multihash {
                    Multihash::from_bytes(&self.chunk_hash).unwrap()
                }
            }
        };
    }
    impl_chunk_hash!(Gossip);
    impl_chunk_hash!(Invite);
    impl_chunk_hash!(QueryFragment);
    impl_chunk_hash!(QueryFragmentOk);
    impl_chunk_hash!(QueryProof);
    impl_chunk_hash!(QueryProofOk);

    macro_rules! impl_from {
        ($source_type:ident, $dest_type:ty, $wrap_type:ty) => {
            impl From<$source_type> for $dest_type {
                fn from(value: $source_type) -> Self {
                    Self {
                        inner: Some(<$wrap_type>::$source_type(value)),
                    }
                }
            }
        };
    }
    impl_from!(Gossip, Request, request::Inner);
    impl_from!(Invite, Request, request::Inner);
    impl_from!(QueryFragment, Request, request::Inner);
    impl_from!(QueryProof, Request, request::Inner);
    impl_from!(QueryFragmentOk, Response, response::Inner);
    impl_from!(QueryProofOk, Response, response::Inner);
    impl_from!(Ok, Response, response::Inner);
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

const MAX_LENGTH: usize = 1 << 30;
#[async_trait::async_trait]
impl request_response::Codec for Codec {
    type Protocol = Protocol;
    type Request = proto::Request;
    type Response = proto::Response;

    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let message = read_length_prefixed(io, MAX_LENGTH).await?;
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
        let message = read_length_prefixed(io, MAX_LENGTH).await?;
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
        assert!(message.len() < MAX_LENGTH);
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
        assert!(message.len() < MAX_LENGTH);
        write_length_prefixed(io, message).await
    }
}

pub type Behavior = request_response::Behaviour<Codec>;
