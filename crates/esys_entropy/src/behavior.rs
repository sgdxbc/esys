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
