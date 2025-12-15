use std::{collections::HashSet, net::SocketAddr};

use anyhow::Result;
use iroh::{EndpointAddr, PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;

use crate::{
    common::create_endpoint,
    iroh_portal::{IrohConnect, IrohListener},
    portal::BoxPortal,
};

#[derive(Deserialize, Serialize)]
pub struct Config {
    pub patch: Vec<Patch>,
}

#[derive(Deserialize, Serialize)]
pub struct Patch {
    pub src: Plug,
    pub dst: Plug,
}

#[derive(Deserialize, Serialize)]
pub enum FromIrohAccept {
    All,
    Only(HashSet<PublicKey>),
}

#[allow(clippy::large_enum_variant)]
#[derive(Deserialize, Serialize)]
pub enum Plug {
    TcpConnect(SocketAddr),
    TcpListen(SocketAddr),
    IrohConnect {
        self_secret_key: Option<SecretKey>,
        self_public_key: Option<PublicKey>,
        target: EndpointAddr,
    },
    // iroh listen and iroh connect seem so similar, I wonder if they could be unified
    IrohListen {
        self_secret_key: SecretKey,

        // feature lacking here, doesn't allow us to specify relays perhaps
        // this should be Option<EndpointAddr>
        self_public_key: Option<PublicKey>,

        accept: FromIrohAccept,
    },
}

impl Plug {
    pub async fn portal(self) -> Result<BoxPortal> {
        async fn iroh_connect(sk: SecretKey, target: EndpointAddr) -> BoxPortal {
            let iroh = create_endpoint(sk).await;
            BoxPortal::new(IrohConnect { iroh, target })
        }

        match self {
            Plug::TcpConnect(socket_addr) => Ok(BoxPortal::new(socket_addr)),
            Plug::TcpListen(socket_addr) => {
                Ok(BoxPortal::new(TcpListener::bind(socket_addr).await?))
            }
            Plug::IrohConnect {
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
                Ok(iroh_connect(sk, target).await)
            }
            Plug::IrohConnect {
                self_secret_key: None,
                self_public_key: None,
                target,
            } => Ok(iroh_connect(SecretKey::generate(&mut rand::rng()), target).await),
            Plug::IrohConnect {
                self_secret_key: Some(sk),
                self_public_key: None,
                target,
            } => Ok(iroh_connect(sk, target).await),
            Plug::IrohConnect {
                self_secret_key: None,
                self_public_key: Some(_),
                ..
            } => anyhow::bail!("Public key provided without secret key"),
            Plug::IrohListen {
                self_secret_key,
                self_public_key,
                accept,
            } => {
                if let Some(pk) = self_public_key {
                    let expected_pk = self_secret_key.public();
                    anyhow::ensure!(
                        pk == expected_pk,
                        "Provided public key {pk:?} does not match the public key {expected_pk:?} \
						 which was derived from the provided secret key."
                    );
                }
                let iroh = create_endpoint(self_secret_key).await;
                Ok(BoxPortal::new(IrohListener { iroh, accept }))
            }
        }
    }
}
