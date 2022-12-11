use hudsucker::{
    async_trait::async_trait,
    certificate_authority::RcgenAuthority,
    hyper::{Body, Request, Response},
    tokio_tungstenite::tungstenite::Message,
    *,
};
use rcgen::generate_simple_self_signed;
use rustls_pemfile as pemfile;
use std::net::SocketAddr;
use tracing::*;

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("Failed to install CTRL+C signal handler");
}

#[derive(Clone)]
struct LogHandler;

#[async_trait]
impl HttpHandler for LogHandler {
    async fn handle_request(
        &mut self,
        _ctx: &HttpContext,
        req: Request<Body>,
    ) -> RequestOrResponse {
        println!("{:?}", req);
        req.into()
    }

    async fn handle_response(&mut self, _ctx: &HttpContext, res: Response<Body>) -> Response<Body> {
        println!("{:?}", res);
        res
    }
}

#[async_trait]
impl WebSocketHandler for LogHandler {
    async fn handle_message(&mut self, _ctx: &WebSocketContext, msg: Message) -> Option<Message> {
        println!("{:?}", msg);
        Some(msg)
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let cert = generate_simple_self_signed(["warcprox-rs CA".to_string()]).unwrap();
    println!("{}", cert.serialize_pem().unwrap());

    let private_key = rustls::PrivateKey(cert.get_key_pair().serialize_der());
    let ca_cert = rustls::Certificate(cert.serialize_der().unwrap());

    let ca = RcgenAuthority::new(private_key, ca_cert, 1_000)
        .expect("Failed to create Certificate Authority");

    let proxy = Proxy::builder()
        .with_addr(SocketAddr::from(([127, 0, 0, 1], 3000)))
        .with_rustls_client()
        .with_ca(ca)
        .with_http_handler(LogHandler)
        .with_websocket_handler(LogHandler)
        .build();

    println!("starting proxy at 127.0.0.1:3000");

    if let Err(e) = proxy.start(shutdown_signal()).await {
        error!("{}", e);
    }
}
