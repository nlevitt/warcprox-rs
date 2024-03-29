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
        help = "Write gzip-compressed warc records"
    )]
    gzip: bool,

    #[arg(
        long,
        default_value = "warcprox-{timestamp17}-{serialno}-{randomtoken}.warc{maybe_dot_gz}",
        help = "Define custom WARC filename using variables {timestamp14}, {timestamp17}, {serialno}, {randomtoken}, {hostname}, {port}, {maybe_dot_gz}"
    )]
    warc_filename: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();
    let address = format!("{}:{}", args.address, args.port);
    let warcproxy = WarcProxy::new(&address, args.gzip, &args.ca_cert, args.warc_filename)?;

    info!("warcprox listening at {}", address);
    warcproxy.run_until_shutdown(shutdown_signal()).await?;

    Ok(())
}

// todo: use https://docs.rs/assert_cmd/latest/assert_cmd/ to test running main
//
// #[cfg(test)]
// mod tests {
//     fn test_address_arg() {}
//     fn test_port_arg() {}
//     fn test_ca_cert_arg() {}
//     fn test_gzip_arg() {}
//     fn test_warc_filename_arg() {}
// }
