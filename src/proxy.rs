use futures::channel::mpsc;
use futures::{SinkExt, Stream};
use hudsucker::async_trait::async_trait;
use hudsucker::hyper::body::Bytes;
use hudsucker::hyper::{Body, Error, Request, Response};
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

impl<T: Stream<Item = Result<Bytes, Error>> + Unpin> Drop for ResponseStream<T> {
    fn drop(&mut self) {
        let mut recorded_url: RecordedUrl = self.recorded_url.take().unwrap();
        recorded_url.response_payload_sha256 = Some(self.sha256.take().unwrap().finalize());
        let mut response_recorder = self.recorder.take().unwrap();
        recorded_url.payload_length = response_recorder.seek(SeekFrom::End(0)).unwrap();
        response_recorder
            .seek(SeekFrom::Start(0))
            .expect("error seeking to start of spooled temp file");
        recorded_url.response_payload_recorder = Some(response_recorder);

        let mut tx = self.tx.take().unwrap();
        tokio::spawn(async move {
            info!("queuing {:?}", recorded_url.uri);
            tx.send(recorded_url).await.expect("failed to queue");
        });
    }
}

#[derive(Debug)]
pub(crate) struct RecordedUrl {
    pub(crate) uri: String,
    pub(crate) response_status_line: Option<Vec<u8>>,
    pub(crate) response_headers: Option<Vec<u8>>,
    pub(crate) response_payload_sha256: Option<Output<Sha256>>,
    pub(crate) response_payload_recorder: Option<SpooledTempFile>,
    pub(crate) payload_length: u64,
}

#[derive(Debug)]
pub(crate) struct ProxyTransactionHandler {
    pub(crate) recorded_url: Option<RecordedUrl>,
    pub(crate) tx: Option<mpsc::Sender<RecordedUrl>>,
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
            response_status_line: None,
            response_headers: None,
            response_payload_sha256: None,
            response_payload_recorder: None,
            payload_length: 0,
        });
        Request::from_parts(parts, body).into()
    }

    async fn handle_response(&mut self, _ctx: &HttpContext, res: Response<Body>) -> Response<Body> {
        let mut recorded_url = self.recorded_url.take().unwrap();
        let (parts, body) = res.into_parts();

        recorded_url.response_status_line = Some(Vec::from(
            format!(
                "{:?} {} {}\r\n",
                parts.version,
                parts.status.as_u16(),
                parts.status.canonical_reason().unwrap()
            )
            .as_bytes(),
        ));
        let mut headers_buf = Vec::new();
        for (name, value) in &parts.headers {
            headers_buf.extend_from_slice(name.as_str().as_bytes());
            headers_buf.extend_from_slice(b": ");
            headers_buf.extend_from_slice(value.as_bytes());
            headers_buf.extend_from_slice(b"\r\n");
        }
        recorded_url.response_headers = Some(headers_buf);

        let body = Body::wrap_stream(ResponseStream::wrap(
            self.tx.take().unwrap(),
            recorded_url,
            body,
        ));
        Response::from_parts(parts, body)
    }
}
