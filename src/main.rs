use std::fs::OpenOptions;
use std::io::{Seek, SeekFrom, Write};
use std::{
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};

use chrono::Utc;
use futures::{channel::mpsc, SinkExt, Stream, StreamExt};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType, DnValue, IsCa,
};
use sha2::{digest::Output, Digest, Sha256};
use tempfile::SpooledTempFile;
use tracing::{error, info};

use hudsucker::{
    async_trait::async_trait,
    certificate_authority::RcgenAuthority,
    hyper::{body::Bytes, Body, Error, Request, Response},
    rustls, HttpContext, HttpHandler, Proxy, RequestOrResponse,
};
use warcio::{WarcRecordBuilder, WarcRecordType, WarcWriter};

const SPOOLED_TEMPFILE_MAX_SIZE: usize = 512 * 1024;

#[derive(Debug)]
struct ResponseStream<T: Stream<Item = Result<Bytes, Error>> + Unpin> {
    tx: Option<mpsc::Sender<RecordedUrl>>,
    recorded_url: Option<RecordedUrl>,
    inner_stream: T,
    sha256: Option<Sha256>,
    recorder: Option<SpooledTempFile>,
}

impl<T: Stream<Item = Result<Bytes, Error>> + Unpin> ResponseStream<T> {
    fn wrap(
        tx: mpsc::Sender<RecordedUrl>,
        recorded_url: RecordedUrl,
        inner_stream: T,
    ) -> ResponseStream<T> {
        ResponseStream {
            recorded_url: Some(recorded_url),
            tx: Some(tx),
            inner_stream,
            sha256: Some(Sha256::new()),
            recorder: Some(SpooledTempFile::new(SPOOLED_TEMPFILE_MAX_SIZE)),
        }
    }
}

impl<T: Stream<Item = Result<Bytes, Error>> + Unpin> Stream for ResponseStream<T> {
    type Item = Result<Bytes, std::io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        match futures::ready!(Pin::new(&mut self.inner_stream).poll_next(cx)) {
            Some(Ok(chunk)) => {
                info!("{:?}", chunk);
                self.sha256.as_mut().unwrap().update(&chunk);
                self.recorder
                    .as_mut()
                    .unwrap()
                    .write_all(&chunk)
                    .expect("error writing to spooled tempfile");
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

impl<T: Stream<Item = Result<Bytes, Error>> + Unpin> Drop for ResponseStream<T> {
    fn drop(&mut self) {
        let mut recorded_url: RecordedUrl = self.recorded_url.take().unwrap();
        recorded_url.response_sha256 = Some(self.sha256.take().unwrap().finalize());
        let mut response_recorder = self.recorder.take().unwrap();
        recorded_url.payload_length = response_recorder.seek(SeekFrom::End(0)).unwrap();
        response_recorder
            .seek(SeekFrom::Start(0))
            .expect("failed to seek to start of spooled tempfile");
        recorded_url.response_recorder = Some(response_recorder);

        let mut tx = self.tx.take().unwrap();
        tokio::spawn(async move {
            info!("queuing {:?}", recorded_url.uri);
            tx.send(recorded_url).await.expect("failed to queue");
        });
    }
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("Failed to install CTRL+C signal handler");
}

#[derive(Debug)]
struct RecordedUrl {
    uri: String,
    response_sha256: Option<Output<Sha256>>,
    response_recorder: Option<SpooledTempFile>,
    payload_length: u64,
}

#[derive(Debug)]
struct ProxyTransactionHandler {
    recorded_url: Option<RecordedUrl>,
    tx: Option<mpsc::Sender<RecordedUrl>>,
}

impl Clone for ProxyTransactionHandler {
    fn clone(&self) -> Self {
        ProxyTransactionHandler {
            // FIXME not kosher but hudsucker ought to be creating a new struct rather than cloning
            recorded_url: None,
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
        let (parts, body) = req.into_parts();
        info!("handle_request uri={:?}", parts.uri.to_string());
        self.recorded_url = Some(RecordedUrl {
            uri: parts.uri.to_string(),
            response_sha256: None,
            response_recorder: None,
            payload_length: 0,
        });
        Request::from_parts(parts, body).into()
    }

    async fn handle_response(&mut self, _ctx: &HttpContext, res: Response<Body>) -> Response<Body> {
        let recorded_url = self.recorded_url.take().unwrap();
        let (parts, body) = res.into_parts();
        let body = Body::wrap_stream(ResponseStream::wrap(
            self.tx.take().unwrap(),
            recorded_url,
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

    let (tx, mut rx) = mpsc::channel::<RecordedUrl>(500);

    let ca = build_ca();
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

    tokio::spawn(async move {
        // WARC/1.0
        // WARC-Type: response
        // WARC-Record-ID: <urn:uuid:6a050210-b1f2-42c9-944a-b1e7c63efec7>
        // WARC-Date: 2023-01-05T08:07:26Z
        // WARC-Target-URI: https://httpbin.org/get
        // WARC-IP-Address: 54.163.169.210
        // Content-Type: application/http;msgtype=response
        // WARC-Payload-Digest: sha1:66777e0225f14e2667e794d3cd1714ba0a639cf7
        // Content-Length: 485
        // WARC-Block-Digest: sha1:666cb28dbda701b12ddbcf779c735aa2e672ac23
        //
        let f = OpenOptions::new()
            .create(true) // .create_new(true)
            .append(true) // .write(true)
            .open("warcprox-rs.warc")?;
        let mut warc_writer = WarcWriter::from(f);

        while let Some(recorded_url) = rx.next().await {
            let record = WarcRecordBuilder::new()
                .warc_type(WarcRecordType::Response)
                .warc_date(Utc::now())
                .warc_target_uri(recorded_url.uri.as_bytes())
                // .warc_ip_address
                .content_type(b"application/http;msgtype=response")
                .content_length(recorded_url.payload_length)
                .body(Box::new(recorded_url.response_recorder.unwrap()))
                .build();
            warc_writer.write_record(record)?;
            info!("wrote to warc: {:?}", recorded_url.uri);
        }

        Ok::<(), std::io::Error>(())
    });

    if let Err(e) = proxy.start(shutdown_signal()).await {
        error!("proxy failed to start: {}", e);
    }
}
