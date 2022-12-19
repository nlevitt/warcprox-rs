use futures::FutureExt;
use futures::future::Map;
use futures::{Stream, StreamExt};
use http_body::Data;
use hudsucker::{
    async_trait::async_trait,
    certificate_authority::RcgenAuthority,
    hyper::body::HttpBody,
    hyper::{Body, Request, Response},
    rustls,
    tokio_tungstenite::tungstenite::Message,
    HttpContext, HttpHandler, Proxy, RequestOrResponse, WebSocketContext, WebSocketHandler,
};
use hyper::body::Bytes;
use hyper::Error;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType, DnValue, IsCa,
};
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::AsyncWriteExt;
use tracing::*; // for mpsc::Receiver

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("Failed to install CTRL+C signal handler");
}

// async fn process_body<'a>(mut body: Body) -> Result<Body, Error> {
//     while let Some(buf) = body.data().await {
//         info!("{:?}", buf);
//     }
//     Ok(body)
// }

// fn process_response(mut res: Response<Body>) -> Result<Response<Body>, Error> {
//     let (mut parts, body) = res.into_parts();
//     // let body = process_body(body);
//     body.poll_next()
//     Ok(Response::from_parts(parts, body))
// }

struct IoStream<T: Stream<Item = Result<Bytes, hyper::Error>> + Unpin>(T);

impl<T: Stream<Item = Result<Bytes, hyper::Error>> + Unpin> Stream for IoStream<T> {
    type Item = Result<Bytes, std::io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        match futures::ready!(Pin::new(&mut self.0).poll_next(cx)) {
            Some(Ok(chunk)) => Poll::Ready(Some(Ok(chunk))),
            Some(Err(err)) => Poll::Ready(Some(Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                err,
            )))),
            None => Poll::Ready(None),
        }
    }
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
        info!("{:?}", req);
        req.into()
    }

    async fn handle_response(&mut self, _ctx: &HttpContext, res: Response<Body>) -> Response<Body> {
        info!("{:?}", res);
        // let res = process_response(res).unwrap();
        let (parts, mut body) = res.into_parts();

        // while let Some(next) = res.data().await {
        //     let chunk = next.unwrap();
        //     tokio::io::stdout().write_all(&chunk).await.unwrap();
        // }

        let body = Body::wrap_stream(IoStream(body).map(|buf| {
            info!("{:?}", buf);
            buf
        }));
        // Self::Body(body) => Box::new(StreamReader::new(IoStream(body))),
        // let data: Map<
        //     Data<Body>,
        //     fn(Option<Result<Bytes, Error>>) -> Option<Result<Bytes, Error>>,
        // > = body.data().map(|buf| {
        //     info!("{:?}", buf.unwrap().unwrap());
        //     buf
        // });
        // let body = Body::wrap_stream(data);
        // let body = Body::from(data);
        // Body::from();
        // data.then(|x| {
        //     x.unwrap().unwrap();
        // });

        // let body = body.then(|buf| async move { x + 3 });
        // let s: dyn Stream = body.into();

        // let body = body.then(|buf| {
        //     info!(buf);
        //     Ok(buf)
        // });
        // Response::from_parts(parts, body.into())
        Response::from_parts(parts, body)
        // Response::new(Body::from('hello'))
    }
}

#[async_trait]
impl WebSocketHandler for LogHandler {
    async fn handle_message(&mut self, _ctx: &WebSocketContext, msg: Message) -> Option<Message> {
        info!("{:?}", msg);
        Some(msg)
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
        .with_http_handler(LogHandler)
        .with_websocket_handler(LogHandler)
        .build();

    info!("proxy listening at {}", addr);

    if let Err(e) = proxy.start(shutdown_signal()).await {
        error!("proxy failed to start: {}", e);
    }
}
