use clap::Parser;
use futures::channel::mpsc;
use hudsucker::Proxy;
use proxy::{ProxyTransactionHandler, RecordedUrl};
use std::net::ToSocketAddrs as _;
use tracing::{error, info};

use crate::postfetch::spawn_postfetch;

mod ca;
mod postfetch;
mod proxy;

async fn shutdown_signal() {
    tokio::signal::ctrl_c().await.unwrap();
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short = 'p', long, default_value_t = 8000)]
    port: u16,

    #[arg(short = 'b', long, default_value = "localhost")]
    address: String,

    #[arg(
        short = 'z',
        long,
        default_value_t = false,
        help = "write gzip-compressed warc records"
    )]
    gzip: bool,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let args = Args::parse();
    let addr = format!("{}:{}", args.address, args.port)
        .to_socket_addrs()
        .unwrap()
        .next()
        .unwrap();

    let (tx, rx) = mpsc::channel::<RecordedUrl>(500);

    spawn_postfetch(rx, args.gzip);

    let ca = ca::build_ca();
    let proxy = Proxy::builder()
        .with_addr(addr)
        .with_rustls_client()
        .with_ca(ca)
        .with_http_handler(ProxyTransactionHandler::new(tx))
        .build();

    info!("proxy listening at {}", addr);
    if let Err(e) = proxy.start(shutdown_signal()).await {
        error!("proxy failed to start: {}", e);
    }
}
