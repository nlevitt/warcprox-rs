use futures::{FutureExt, Stream, StreamExt, TryStreamExt};
use hudsucker::{
    async_trait::async_trait,
    certificate_authority::RcgenAuthority,
    hyper::{Body, Request, Response},
    rustls,
    tokio_tungstenite::tungstenite::Message,
    HttpContext, HttpHandler, Proxy, RequestOrResponse, WebSocketContext,
};
use hyper::body::{Bytes, HttpBody};
use hyper::Error;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType, DnValue, IsCa,
};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use sha2::digest::FixedOutput;
use tracing::*; // for mpsc::Receiver

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("Failed to install CTRL+C signal handler");
}

#[derive(Clone)]
struct WarcProxyHandler;

#[async_trait]
impl HttpHandler for WarcProxyHandler {
    async fn handle_request(
        &mut self,
        _ctx: &HttpContext,
        req: Request<Body>,
    ) -> RequestOrResponse {
        info!("{:?}", req);
        req.into()
    }

    async fn handle_response(&mut self, _ctx: &HttpContext, res: Response<Body>) -> Response<Body> {
        info!("{:?}", res);
        let (parts, body) = res.into_parts();

        let mut sha256 = Sha256::new();
        let body = body.map_data(|buf| {
            info!("{:?}", buf);
            sha256.update(&buf);
            buf
        }).into_inner();
        Response::from_parts(parts, body)
    }
}

fn build_ca() -> RcgenAuthority {
    let mut ca_cert_params = CertificateParams::default();
    ca_cert_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    ca_cert_params.distinguished_name = DistinguishedName::new();
    ca_cert_params.distinguished_name.push(
        DnType::CommonName,
        DnValue::PrintableString("warcprox-rs CA".to_string()),
    );
    let ca_cert = Certificate::from_params(ca_cert_params).unwrap();
    info!("created CA cert:\n{}", ca_cert.serialize_pem().unwrap());

    let private_key = rustls::PrivateKey(ca_cert.get_key_pair().serialize_der());
    let ca_cert = rustls::Certificate(ca_cert.serialize_der().unwrap());

    let ca = RcgenAuthority::new(private_key, ca_cert, 1_000)
        .expect("Failed to create Certificate Authority");
    ca
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let ca = build_ca();
    let addr = SocketAddr::from(([127, 0, 0, 1], 8000));
    let proxy = Proxy::builder()
        .with_addr(addr)
        .with_rustls_client()
        .with_ca(ca)
        .with_http_handler(WarcProxyHandler)
        .build();

    info!("proxy listening at {}", addr);

    if let Err(e) = proxy.start(shutdown_signal()).await {
        error!("proxy failed to start: {}", e);
    }
}
