use crate::common::AsyncReadWrite;
use crate::config::FromIrohAccept;
use crate::listener::Listener;

pub struct IrohListener {
    pub endpoint: iroh::Endpoint,
    pub accept: FromIrohAccept,
}

impl Listener for IrohListener {
    async fn accept(&mut self) -> impl AsyncReadWrite + 'static {
        loop {
            let Some(incomming) = self.endpoint.accept().await else {
                continue;
            };

            // potential denial of service here if an unathenticated peer
            // begins a connection then dawdles
            // might need to keep a set of inflight connections and attempt to join on them
            let conn = incomming.await;

            let Ok(conn) = conn else {
                continue;
            };

            if let FromIrohAccept::Only(allowed) = &self.accept && !allowed.contains(&conn.remote_id()) {
                conn.close(0u32.into(), b"nope");
                continue;
            }

            // we assume that each peer will only make one connection, this is limiting
            // and deserves remedy
            let Ok((send, recv)) = conn.accept_bi().await else {
                continue;
            };

            return Box::new(tokio::io::join(recv, send));
        }
    }
}
