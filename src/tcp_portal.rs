use std::net::SocketAddr;

use anyhow::Result;

use tokio::net::TcpListener;
use tokio::net::TcpStream;

use crate::common::AsyncReadWrite;
use crate::portal::Portal;

impl Portal for TcpListener {
    async fn link(&mut self) -> Result<impl AsyncReadWrite + 'static> {
        let (stream, _) = TcpListener::accept(self).await?;
        Ok(stream)
    }
}

impl Portal for SocketAddr {
    async fn link(&mut self) -> Result<impl AsyncReadWrite + 'static> {
        TcpStream::connect(*self).await.map_err(Into::into)
    }
}
