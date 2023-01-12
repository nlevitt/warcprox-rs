use futures::channel::{mpsc, oneshot};
use futures::{SinkExt, Stream};
use hudsucker::async_trait::async_trait;
use hudsucker::hyper::body::Bytes;
use hudsucker::hyper::{Body, Error, HeaderMap, Method, Request, Response};
use hudsucker::{HttpContext, HttpHandler, RequestOrResponse};
use sha2::digest::Output;
use sha2::{Digest, Sha256};
use std::fmt::Debug;
use std::io::{Seek, SeekFrom, Write};
use std::pin::Pin;
use std::task::{Context, Poll};
use tempfile::SpooledTempFile;
use tracing::info;

const SPOOLED_TEMPFILE_MAX_SIZE: usize = 512 * 1024;

#[derive(Debug)]
struct PayloadStream<T: Stream<Item = Result<Bytes, Error>> + Unpin> {
    inner_stream: T,
    sha256: Option<Sha256>,
    recorder: Option<SpooledTempFile>,
    tx: Option<oneshot::Sender<Payload>>,
}

impl<T: Stream<Item = Result<Bytes, Error>> + Unpin> PayloadStream<T> {
    fn wrap(tx: oneshot::Sender<Payload>, inner_stream: T) -> PayloadStream<T> {
        PayloadStream {
            inner_stream,
            sha256: Some(Sha256::new()),
            recorder: Some(SpooledTempFile::new(SPOOLED_TEMPFILE_MAX_SIZE)),
            tx: Some(tx),
        }
    }
}

impl<T: Stream<Item = Result<Bytes, Error>> + Unpin> Stream for PayloadStream<T> {
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
                    .expect("error writing to spooled temp file");
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

impl<T: Stream<Item = Result<Bytes, Error>> + Unpin> Drop for PayloadStream<T> {
    fn drop(&mut self) {
        let mut payload: SpooledTempFile = self.recorder.take().unwrap();
        let sha256: Output<Sha256> = self.sha256.take().unwrap().finalize();
        let length = payload.seek(SeekFrom::End(0)).unwrap();
        info!("drop: length={}", length);
        payload.seek(SeekFrom::Start(0)).unwrap();

        self.tx
            .take()
            .unwrap()
            .send(Payload {
                payload,
                sha256,
                length,
            })
            .unwrap();
    }
}

#[derive(Debug)]
pub(crate) struct Payload {
    pub(crate) sha256: Output<Sha256>,
    pub(crate) payload: SpooledTempFile,
    pub(crate) length: u64,
}

#[derive(Debug)]
pub(crate) struct RecordedUrl {
    pub(crate) uri: String,
    pub(crate) request_line: Option<Vec<u8>>,
    pub(crate) request_headers: Option<Vec<u8>>,
    pub(crate) request_payload: Option<Payload>,
    pub(crate) response_status_line: Option<Vec<u8>>,
    pub(crate) response_headers: Option<Vec<u8>>,
    pub(crate) response_payload: Option<Payload>,
}

#[derive(Debug)]
pub(crate) struct ProxyTransactionHandler {
    pub(crate) recorded_url: Option<RecordedUrl>,
    pub(crate) recorded_url_tx: Option<mpsc::Sender<RecordedUrl>>,
    request_payload_rx: Option<oneshot::Receiver<Payload>>,
    is_connect: bool,
}

impl ProxyTransactionHandler {
    pub(crate) fn new(recorded_url_tx: mpsc::Sender<RecordedUrl>) -> Self {
        Self {
            recorded_url_tx: Some(recorded_url_tx),
            recorded_url: None,
            request_payload_rx: None,
            is_connect: false,
        }
    }
}

impl Clone for ProxyTransactionHandler {
    fn clone(&self) -> Self {
        ProxyTransactionHandler {
            // FIXME not kosher but hudsucker ought to be creating a new struct rather than cloning
            recorded_url: None,
            recorded_url_tx: self.recorded_url_tx.clone(),
            request_payload_rx: None,
            is_connect: false,
        }
    }
}

fn headers_as_bytes(headers: &HeaderMap) -> Vec<u8> {
    let mut buf = Vec::new();
    for (name, value) in headers {
        buf.extend_from_slice(name.as_str().as_bytes());
        buf.extend_from_slice(b": ");
        buf.extend_from_slice(value.as_bytes());
        buf.extend_from_slice(b"\r\n");
    }
    buf
}

#[async_trait]
impl HttpHandler for ProxyTransactionHandler {
    async fn handle_request(
        &mut self,
        _ctx: &HttpContext,
        req: Request<Body>,
    ) -> RequestOrResponse {
        let (parts, body) = req.into_parts();
        if parts.method == Method::CONNECT {
            self.is_connect = true;
            return Request::from_parts(parts, body).into();
        }

        info!("handle_request uri={:?}", parts.uri.to_string());

        let request_line = Some(Vec::from(
            format!(
                "{} {} {:?}\r\n",
                parts.method,
                parts.uri.path_and_query().unwrap(),
                parts.version
            )
            .as_bytes(),
        ));
        self.recorded_url = Some(RecordedUrl {
            uri: parts.uri.to_string(),
            request_line,
            request_headers: Some(headers_as_bytes(&parts.headers)),
            request_payload: None,
            response_status_line: None,
            response_headers: None,
            response_payload: None,
        });

        let (request_payload_tx, request_payload_rx) = oneshot::channel::<Payload>();
        let body = Body::wrap_stream(PayloadStream::wrap(request_payload_tx, body));
        self.request_payload_rx = Some(request_payload_rx);
        Request::from_parts(parts, body).into()
    }

    async fn handle_response(
        &mut self,
        _ctx: &HttpContext,
        response: Response<Body>,
    ) -> Response<Body> {
        info!(
            "ProxyTransactionHandler::handle_response: self.is_connect={}",
            self.is_connect
        );
        if self.is_connect {
            return response;
        }

        let mut recorded_url = self.recorded_url.take().unwrap();

        let request_payload = self.request_payload_rx.take().unwrap().await.unwrap();
        recorded_url.request_payload = Some(request_payload);

        let (parts, body) = response.into_parts();

        recorded_url.response_status_line = Some(Vec::from(
            format!(
                "{:?} {} {}\r\n",
                parts.version,
                parts.status.as_u16(),
                parts.status.canonical_reason().unwrap()
            )
            .as_bytes(),
        ));
        recorded_url.response_headers = Some(headers_as_bytes(&parts.headers));

        let (response_payload_tx, response_payload_rx) = oneshot::channel::<Payload>();
        let body = Body::wrap_stream(PayloadStream::wrap(response_payload_tx, body));

        let mut recorded_url_tx = self.recorded_url_tx.take().unwrap();
        tokio::spawn(async move {
            let payload = response_payload_rx.await.unwrap();
            recorded_url.response_payload = Some(payload);
            info!("queuing {:?}", recorded_url.uri);
            recorded_url_tx.send(recorded_url).await.unwrap();
        });

        Response::from_parts(parts, body)
    }
}
