use futures::channel::mpsc;
use hudsucker::Proxy;
use proxy::{ProxyTransactionHandler, RecordedUrl};
use std::net::SocketAddr;
use tracing::{error, info};

use crate::postfetch::spawn_postfetch;

mod ca;
mod postfetch;
mod proxy;

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to install ctrl+c signal handler");
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let (tx, rx) = mpsc::channel::<RecordedUrl>(500);

    spawn_postfetch(rx);

    let ca = ca::build_ca();
    let addr = SocketAddr::from(([127, 0, 0, 1], 8000));
    let proxy = Proxy::builder()
        .with_addr(addr)
        .with_rustls_client()
        .with_ca(ca)
        .with_http_handler(ProxyTransactionHandler {
            tx: Some(tx),
            recorded_url: None,
        })
        .build();

    info!("proxy listening at {}", addr);
    if let Err(e) = proxy.start(shutdown_signal()).await {
        error!("proxy failed to start: {}", e);
    }
}
