use std::net::SocketAddr;

use anyhow::Result;
use iroh::{EndpointAddr, SecretKey};
use tokio::net::TcpStream;

use crate::{
    common::{box_stream, create_endpoint, BoxStream, ALPN},
    config::DstAddr,
};

#[allow(clippy::large_enum_variant)]
#[derive(Clone)]
pub enum Target {
    Ip(SocketAddr),
    Iroh {
        self_secret_key: SecretKey,
        target: EndpointAddr,
    },
}

impl Target {
    pub fn from_addr(addr: DstAddr) -> Result<Self> {
        let ret = match addr {
            DstAddr::Tcp(socket_addr) => Target::Ip(socket_addr),
            DstAddr::Iroh {
                self_secret_key: Some(sk),
                self_public_key: Some(pk),
                target,
            } => {
                anyhow::ensure!(
                    pk == sk.public(),
                    "The provided public key is not consistent with the provided secret key. \
                     The expected public key is {:?} but {:?} was provided. \
                     Consider changing the provided public key. Alternatively, you can omit \
					 the public key and it will be automatically inferred.",
                    sk.public(),
                    pk
                );
                Target::Iroh {
                    self_secret_key: sk,
                    target,
                }
            }

            DstAddr::Iroh {
                self_secret_key: None,
                self_public_key: None,
                target,
            } => Target::Iroh {
                self_secret_key: SecretKey::generate(&mut rand::rng()),
                target,
            },
            DstAddr::Iroh {
                self_secret_key: Some(sk),
                self_public_key: None,
                target,
            } => Target::Iroh {
                self_secret_key: sk,
                target,
            },
            DstAddr::Iroh {
                self_secret_key: None,
                self_public_key: Some(_),
                ..
            } => anyhow::bail!("Public key provided without secret key"),
        };

        Ok(ret)
    }

    pub async fn connect(&self) -> Result<BoxStream> {
        match self {
            Target::Ip(socket_addr) => Ok(box_stream(TcpStream::connect(socket_addr).await?)),
            Target::Iroh {
                self_secret_key: my_secret_key,
                target,
            } => {
                let endpoint = create_endpoint(my_secret_key.clone()).await;
                let conn = endpoint.connect(target.clone(), ALPN).await?;
                let (send, recv) = conn.open_bi().await?;
                Ok(box_stream(tokio::io::join(recv, send)))
            }
        }
    }
}
