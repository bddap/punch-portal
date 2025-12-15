use std::pin::Pin;

use iroh::{
    Endpoint, SecretKey,
    discovery::{dns::DnsDiscovery, mdns::MdnsDiscovery, pkarr::PkarrPublisher},
};
use tokio::io::{AsyncRead, AsyncWrite};

pub trait AsyncReadWrite: AsyncRead + AsyncWrite + Unpin + Send + Sync {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + Sync> AsyncReadWrite for T {}

pub type BoxStream = Pin<Box<dyn AsyncReadWrite + 'static>>;

pub fn box_stream<S: AsyncReadWrite + 'static>(s: S) -> BoxStream {
    Box::pin(s)
}

pub const ALPN: &[u8] = b"/punch-portal/0";

pub async fn create_endpoint(sk: SecretKey) -> Endpoint {
    Endpoint::builder()
        .secret_key(sk)
        .discovery(PkarrPublisher::n0_dns())
        .discovery(DnsDiscovery::n0_dns())
        .discovery(MdnsDiscovery::builder())
        .alpns([ALPN.to_vec()].to_vec())
        .bind()
        .await
        .unwrap()
}
