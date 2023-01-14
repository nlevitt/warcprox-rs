use futures::channel::{mpsc, oneshot};
use futures::{SinkExt, Stream};
use hudsucker::async_trait::async_trait;
use hudsucker::hyper::body::Bytes;
use hudsucker::hyper::{Body, Error, Method, Request, Response};
use hudsucker::{HttpContext, HttpHandler, RequestOrResponse};
use sha2::digest::Output;
use sha2::{Digest, Sha256};
use std::fmt::Debug;
use std::io::{Seek, SeekFrom, Write};
use std::pin::Pin;
use std::task::{Context, Poll};
use tempfile::SpooledTempFile;

use crate::recorded_url::{Payload, RecordedUrl, RecordedUrlBuilder};

const SPOOLED_TEMPFILE_MAX_SIZE: usize = 512 * 1024;

#[derive(Debug)]
struct PayloadStream<T: Stream<Item = Result<Bytes, Error>> + Unpin> {
    inner_stream: T,
    sha256: Option<Sha256>,
    recorder: Option<SpooledTempFile>,
    tx: Option<oneshot::Sender<Payload>>,
}

impl<T: Stream<Item = Result<Bytes, Error>> + Unpin> PayloadStream<T> {
    fn wrap(inner_stream: T, tx: oneshot::Sender<Payload>) -> PayloadStream<T> {
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
                self.sha256.as_mut().unwrap().update(&chunk);
                self.recorder.as_mut().unwrap().write_all(&chunk).unwrap();
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
pub(crate) struct ProxyTransactionHandler {
    pub(crate) recorded_url_builder: Option<RecordedUrlBuilder>,
    pub(crate) recorded_url_tx: Option<mpsc::Sender<RecordedUrl>>,
    request_payload_rx: Option<oneshot::Receiver<Payload>>,
    is_connect: bool,
}

impl ProxyTransactionHandler {
    pub(crate) fn new(recorded_url_tx: mpsc::Sender<RecordedUrl>) -> Self {
        Self {
            recorded_url_tx: Some(recorded_url_tx),
            recorded_url_builder: None,
            request_payload_rx: None,
            is_connect: false,
        }
    }
}

impl Clone for ProxyTransactionHandler {
    fn clone(&self) -> Self {
        ProxyTransactionHandler {
            // FIXME not kosher but hudsucker ought to be creating a new struct rather than cloning
            recorded_url_builder: None,
            recorded_url_tx: self.recorded_url_tx.clone(),
            request_payload_rx: None,
            is_connect: false,
        }
    }
}

fn await_payloads_and_queue_postfetch(
    recorded_url_builder: RecordedUrlBuilder,
    request_payload_rx: oneshot::Receiver<Payload>,
    response_payload_rx: oneshot::Receiver<Payload>,
    mut recorded_url_tx: mpsc::Sender<RecordedUrl>,
) {
    tokio::spawn(async move {
        let request_payload = request_payload_rx.await.unwrap();
        let response_payload = response_payload_rx.await.unwrap();

        let recorded_url = recorded_url_builder
            .request_payload(request_payload)
            .response_payload(response_payload)
            .build();
        recorded_url_tx.send(recorded_url).await.unwrap();
    });
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

        self.recorded_url_builder =
            Some(RecordedUrlBuilder::new(parts.uri.to_string()).request_parts(&parts));
        let (request_payload_tx, request_payload_rx) = oneshot::channel::<Payload>();
        let body = Body::wrap_stream(PayloadStream::wrap(body, request_payload_tx));
        self.request_payload_rx = Some(request_payload_rx);
        Request::from_parts(parts, body).into()
    }

    async fn handle_response(
        &mut self,
        _ctx: &HttpContext,
        response: Response<Body>,
    ) -> Response<Body> {
        if self.is_connect {
            return response;
        }

        let (parts, body) = response.into_parts();
        let mut recorded_url_builder = self.recorded_url_builder.take().unwrap();
        recorded_url_builder = recorded_url_builder.response_parts(&parts);

        let (response_payload_tx, response_payload_rx) = oneshot::channel::<Payload>();
        let body = Body::wrap_stream(PayloadStream::wrap(body, response_payload_tx));

        await_payloads_and_queue_postfetch(
            recorded_url_builder,
            self.request_payload_rx.take().unwrap(),
            response_payload_rx,
            self.recorded_url_tx.take().unwrap(),
        );

        Response::from_parts(parts, body)
    }
}
