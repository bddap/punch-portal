mod common;
mod config;
mod iroh_portal;
mod portal;
mod tcp_portal;

use std::{path::PathBuf, sync::Arc};

use anyhow::{Context, Result};
use clap::Parser as _;
use futures::future::try_join_all;
use iroh::{
    EndpointAddr, RelayConfig, SecretKey, TransportAddr, defaults::prod::default_relay_map,
};
use tokio::{fs::read_to_string, io::copy_bidirectional};

use crate::{
    config::{Config, DstAddr, Forward, FromIrohAccept, SrcAddr},
    portal::Portal,
};

#[derive(clap::Parser)]
enum Cli {
    Start { config: PathBuf },
    Generate { server: PathBuf, client: PathBuf },
}

#[tokio::main]
async fn main() -> Result<()> {
    Cli::parse().run().await
}

impl Cli {
    async fn run(self) -> Result<()> {
        match self {
            Cli::Start { config } => start(config).await,
            Cli::Generate { server, client } => generate(server, client).await,
        }
    }
}

async fn start(config: PathBuf) -> Result<()> {
    let config_raw = read_to_string(&config)
        .await
        .with_context(|| format!("reading {:?}", &config))?;
    let config: Config =
        toml::from_str(&config_raw).with_context(|| format!("parsing {:?}", &config))?;
    try_join_all(config.forward.into_iter().map(forward)).await?;
    Ok(())
}

async fn generate(server: PathBuf, client: PathBuf) -> Result<()> {
    let server_sk = SecretKey::generate(&mut rand::rng());
    let client_sk = SecretKey::generate(&mut rand::rng());

    write_config(
        server,
        Config {
            forward: [Forward {
                src: SrcAddr::Iroh {
                    self_secret_key: server_sk.clone(),
                    self_public_key: Some(server_sk.public()),
                    accept: FromIrohAccept::Only([client_sk.public()].into()),
                },
                dst: DstAddr::Tcp(([127, 0, 0, 1], 8080).into()),
            }]
            .into(),
        },
    )
    .await?;
    write_config(
        client,
        Config {
            forward: [Forward {
                src: SrcAddr::Tcp(([127, 0, 0, 1], 9090).into()),
                dst: DstAddr::Iroh {
                    self_secret_key: Some(client_sk.clone()),
                    self_public_key: Some(client_sk.public()),
                    target: EndpointAddr::from_parts(server_sk.public(), default_relays()),
                },
            }]
            .into(),
        },
    )
    .await?;

    Ok(())
}

fn default_relays() -> Vec<TransportAddr> {
    let relays: Vec<Arc<RelayConfig>> = default_relay_map().relays();
    relays
        .into_iter()
        .map(|r| TransportAddr::Relay(r.url.clone()))
        .collect()
}

async fn write_config(p: PathBuf, c: Config) -> Result<()> {
    let s = toml::to_string_pretty(&c).unwrap();
    tokio::fs::write(&p, s)
        .await
        .with_context(|| format!("writing {:?}", &p))?;
    Ok(())
}

async fn forward(forward: Forward) -> Result<()> {
    let mut listener = forward.src.portal().await?;
    let mut forward_to = forward.dst.portal().await?;
    loop {
        let mut inbound = listener.link().await?;

        // inefficiency here, shouldn't need to wait for
        // outbound connect before accepting more links
        let mut outbound = forward_to.link().await?;

        tokio::spawn(async move {
            let _ = copy_bidirectional(&mut inbound, &mut outbound).await;
        });
    }
}
