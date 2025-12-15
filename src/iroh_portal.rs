use anyhow::Result;
use iroh::{Endpoint, EndpointAddr};

use crate::common::{ALPN, AsyncReadWrite};
use crate::config::FromIrohAccept;
use crate::portal::Portal;

pub struct IrohListener {
    pub iroh: Endpoint,
    pub accept: FromIrohAccept,
}

impl Portal for IrohListener {
	async fn link(&mut self) -> Result<impl AsyncReadWrite + 'static> {
		loop {
            let Some(incomming) = self.iroh.accept().await else {
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
            let Ok((send, mut recv)) = conn.accept_bi().await else {
                continue;
            };

			recv.read_exact(&mut [0u8]).await?;
			
            return Ok(tokio::io::join(recv, send));
        }
    }
}

pub struct IrohConnect {
    pub iroh: Endpoint,
    pub target: EndpointAddr,
}

impl Portal for IrohConnect {
	async fn link(&mut self) -> Result<impl AsyncReadWrite + 'static> {
		let conn = self.iroh.connect(self.target.clone(), ALPN).await?;
		let (mut send, recv) = conn.open_bi().await?;
		
		send.write_all(&[0u8]).await?;
		
		Ok(tokio::io::join(recv, send))
	}
}
