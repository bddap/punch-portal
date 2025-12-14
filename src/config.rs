use std::{collections::HashSet, net::SocketAddr};

use iroh::{EndpointAddr, PublicKey, SecretKey};
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
pub struct Config {
    pub forward: Vec<Forward>,
}

#[derive(Deserialize, Serialize)]
pub struct Forward {
    pub src: SrcAddr,
    pub dst: DstAddr,
}

#[allow(clippy::large_enum_variant)]
#[derive(Deserialize, Serialize)]
pub enum SrcAddr {
    Tcp(SocketAddr),
    Iroh {
        self_secret_key: SecretKey,
        self_public_key: Option<PublicKey>,
        accept: FromIrohAccept,
    },
}

#[derive(Deserialize, Serialize)]
pub enum FromIrohAccept {
    All,
    Only(HashSet<PublicKey>),
}

#[allow(clippy::large_enum_variant)]
#[derive(Deserialize, Serialize, Clone)]
pub enum DstAddr {
    Tcp(SocketAddr),
    Iroh {
        self_secret_key: Option<SecretKey>,
        self_public_key: Option<PublicKey>,
        target: EndpointAddr,
    },
}
