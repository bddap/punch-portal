use std::future::Future;

use anyhow::Result;
use futures::FutureExt;
use futures::future::BoxFuture;

use crate::common::{AsyncReadWrite, BoxStream, box_stream};

// is "Portal" the right name?
// Perhaps it's more of a "Socket". An "Endpoint".
pub trait Portal: Send {
    fn link<'a>(
        &'a mut self,
    ) -> impl Future<Output = Result<impl AsyncReadWrite + 'static>> + Send + 'a;
}

trait DynPortal: Send {
    fn dyn_link(&mut self) -> BoxFuture<'_, Result<BoxStream>>;
}

impl<T: Portal + ?Sized> DynPortal for T {
    fn dyn_link<'a>(&'a mut self) -> BoxFuture<'a, Result<BoxStream>> {
        async move { Ok(box_stream(self.link().await?)) }.boxed()
    }
}

pub struct BoxPortal(Box<dyn DynPortal>);

impl BoxPortal {
    pub fn new<T: Portal + 'static>(portal: T) -> Self {
        BoxPortal(Box::new(portal))
    }
}

impl Portal for BoxPortal {
    fn link<'a>(
        &'a mut self,
    ) -> impl Future<Output = Result<impl AsyncReadWrite + 'static>> + Send + 'a {
        self.0.dyn_link()
    }
}
