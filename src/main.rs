use futures::Stream;
use hudsucker::{
    async_trait::async_trait,
    certificate_authority::RcgenAuthority,
    hyper::{body::Bytes, Body, Error, Request, Response},
    rustls, HttpContext, HttpHandler, Proxy, RequestOrResponse,
};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType, DnValue, IsCa,
};
use sha2::digest::Output;
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use tracing::{error, info};

#[derive(Debug)]
enum Sha256State {
    InProgress(Sha256),
    Finalized(Output<Sha256>),
}

impl Default for Sha256State {
    fn default() -> Self {
        Sha256State::InProgress(Sha256::new())
    }
}

#[derive(Debug)]
struct ResponseStream<T: Stream<Item = Result<Bytes, Error>> + Unpin> {
    inner_stream: T,
    sha256state: Sha256State,
}

impl<T: Stream<Item = Result<Bytes, Error>> + Unpin> ResponseStream<T> {
    fn wrap(inner_stream: T) -> ResponseStream<T> {
        ResponseStream {
            inner_stream,
            sha256state: Sha256State::InProgress(Sha256::new()),
        }
    }
}

impl<T: Stream<Item = Result<Bytes, Error>> + Unpin> Stream for ResponseStream<T> {
    type Item = Result<Bytes, std::io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        match futures::ready!(Pin::new(&mut self.inner_stream).poll_next(cx)) {
            Some(Ok(chunk)) => {
                info!("{:?}", chunk);
                if let Sha256State::InProgress(sha256) = &mut self.sha256state {
                    sha256.update(&chunk);
                }
                Poll::Ready(Some(Ok(chunk)))
            }
            Some(Err(err)) => Poll::Ready(Some(Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                err,
            )))),
            None => {
                // https://rust-unofficial.github.io/patterns/idioms/mem-replace.html
                if let Sha256State::InProgress(sha256) = std::mem::take(&mut self.sha256state) {
                    self.sha256state = Sha256State::Finalized(sha256.finalize());
                }
                info!("{:?}", self.sha256state);
                Poll::Ready(None)
            }
        }
    }
}

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
        info!("handle_response before {:?}", res);
        let (parts, body) = res.into_parts();
        let body = Body::wrap_stream(ResponseStream::wrap(body));
        let rv = Response::from_parts(parts, body);
        info!("handle_response after {:?}", rv);
        rv
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
    // console_subscriber::init();
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
