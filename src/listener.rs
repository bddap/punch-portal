use std::future::Future;

use futures::future::BoxFuture;
use futures::FutureExt;

use tokio::net::TcpListener;

use crate::common::{box_stream, AsyncReadWrite, BoxStream};

pub trait Listener: Send {
    fn accept<'a>(&'a mut self) -> impl Future<Output = impl AsyncReadWrite + 'static> + Send + 'a;
}

impl Listener for TcpListener {
    async fn accept(&mut self) -> impl AsyncReadWrite + 'static {
        loop {
            if let Ok((stream, _)) = TcpListener::accept(self).await {
                return stream;
            }
        }
    }
}

pub trait DynListener {
    fn dyn_accept(&mut self) -> BoxFuture<'_, BoxStream>;
}

impl<T: Listener + ?Sized> DynListener for T {
    fn dyn_accept<'a>(&'a mut self) -> BoxFuture<'a, BoxStream> {
        async move { box_stream(self.accept().await) }.boxed()
    }
}
