use futures::{channel::mpsc, SinkExt, Stream, StreamExt};
use hudsucker::{
    async_trait::async_trait,
    certificate_authority::RcgenAuthority,
    hyper::{body::Bytes, Body, Error, Request, Response},
    rustls, HttpContext, HttpHandler, Proxy, RequestOrResponse,
};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType, DnValue, IsCa,
};
use sha2::{digest::Output, Digest, Sha256};
use std::{
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};
use tempfile::SpooledTempFile;
use tracing::{error, info}; // ::channel;

#[derive(Debug)]
struct BodyStream<T: Stream<Item = Result<Bytes, Error>> + Unpin> {
    tx: Option<mpsc::Sender<RequestInfo>>,
    request_info: Option<RequestInfo>,
    inner_stream: T,
    sha256: Option<Sha256>,
}

impl<T: Stream<Item = Result<Bytes, Error>> + Unpin> BodyStream<T> {
    fn wrap(
        tx: mpsc::Sender<RequestInfo>,
        request_info: RequestInfo,
        inner_stream: T,
    ) -> BodyStream<T> {
        BodyStream {
            request_info: Some(request_info),
            tx: Some(tx),
            inner_stream,
            sha256: Some(Sha256::new()),
        }
    }
}

impl<T: Stream<Item = Result<Bytes, Error>> + Unpin> Stream for BodyStream<T> {
    type Item = Result<Bytes, std::io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        match futures::ready!(Pin::new(&mut self.inner_stream).poll_next(cx)) {
            Some(Ok(chunk)) => {
                info!("{:?}", chunk);
                self.sha256.as_mut().unwrap().update(&chunk);
                Poll::Ready(Some(Ok(chunk)))
            }
            Some(Err(err)) => Poll::Ready(Some(Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                err,
            )))),
            None => Poll::Ready(None),
        }
    }
}

impl<T: Stream<Item = Result<Bytes, Error>> + Unpin> Drop for BodyStream<T> {
    fn drop(&mut self) {
        let mut request_info = self.request_info.take().unwrap();
        request_info.response_sha256 = Some(self.sha256.take().unwrap().finalize());
        let mut tx = self.tx.take().unwrap();
        tokio::spawn(async move {
            info!("queuing {:?}", request_info.uri);
            tx.send(request_info).await.expect("failed to queue");
        });
    }
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("Failed to install CTRL+C signal handler");
}

#[derive(Debug)]
struct RequestInfo {
    uri: String,
    response_sha256: Option<Output<Sha256>>,
    response_buf: Option<SpooledTempFile>,
}

#[derive(Debug)]
struct ProxyTransactionHandler {
    request_info: Option<RequestInfo>,
    tx: Option<mpsc::Sender<RequestInfo>>,
}

impl Clone for ProxyTransactionHandler {
    fn clone(&self) -> Self {
        ProxyTransactionHandler {
            // FIXME not kosher but hudsucker ought to be creating a new struct rather than cloning
            request_info: None,
            tx: self.tx.clone(),
        }
    }
}

#[async_trait]
impl HttpHandler for ProxyTransactionHandler {
    async fn handle_request(
        &mut self,
        _ctx: &HttpContext,
        req: Request<Body>,
    ) -> RequestOrResponse {
        info!("{:?}", req);
        let (parts, body) = req.into_parts();
        info!("handle_request uri={:?}", parts.uri.to_string());
        self.request_info = Some(RequestInfo {
            uri: parts.uri.to_string(),
            response_sha256: None,
            response_buf: None,
        });
        Request::from_parts(parts, body).into()
    }

    async fn handle_response(&mut self, _ctx: &HttpContext, res: Response<Body>) -> Response<Body> {
        let request_info = self.request_info.take().unwrap();
        let (parts, body) = res.into_parts();
        let body = Body::wrap_stream(BodyStream::wrap(
            self.tx.take().unwrap(),
            request_info,
            body,
        ));
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
    // console_subscriber::init();
    tracing_subscriber::fmt::init();

    let (tx, mut rx) = mpsc::channel::<RequestInfo>(500);

    let ca = build_ca();
    let addr = SocketAddr::from(([127, 0, 0, 1], 8000));
    let proxy = Proxy::builder()
        .with_addr(addr)
        .with_rustls_client()
        .with_ca(ca)
        .with_http_handler(ProxyTransactionHandler {
            tx: Some(tx),
            request_info: None,
        })
        .build();

    info!("proxy listening at {}", addr);

    tokio::spawn(async move {
        while let Some(request_info) = rx.next().await {
            info!("dequeued {:?}", request_info.uri);
        }
    });

    if let Err(e) = proxy.start(shutdown_signal()).await {
        error!("proxy failed to start: {}", e);
    }
}
