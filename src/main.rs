use clap::Parser;
use tracing::info;
use warcprox_rs::WarcProxy;

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
        short = 'c',
        long = "cacert",
        default_value = "./warcprox-rs-ca.pem",
        help = "CA certificate file. If it does not exist, it will be created"
    )]
    ca_cert: String,

    #[arg(
        short = 'z',
        long,
        default_value_t = false,
        help = "write gzip-compressed warc records"
    )]
    gzip: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();
    let address = format!("{}:{}", args.address, args.port);
    let warcproxy = WarcProxy::new(&address, args.gzip, &args.ca_cert)?;

    info!("warcprox listening at {}", address);
    warcproxy.start(shutdown_signal()).await?;

    Ok(())
}
