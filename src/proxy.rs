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
use tracing::debug;

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
        let length = payload.seek(SeekFrom::End(0)).unwrap() as usize;
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
        request: Request<Body>,
    ) -> RequestOrResponse {
        debug!("request={:?}", request);
        let (parts, body) = request.into_parts();
        if parts.method == Method::CONNECT {
            self.is_connect = true;
            return Request::from_parts(parts, body).into();
        }

        self.recorded_url_builder = Some(RecordedUrl::builder().request_parts(&parts));
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
        debug!("response={:?}", response);
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

#[cfg(test)]
mod tests {
    extern crate test_common;
    use crate::ca::certauth;
    use crate::proxy::ProxyTransactionHandler;
    use crate::proxy_client::proxy_client;
    use crate::recorded_url::RecordedUrl;
    use chrono::Utc;
    use futures::channel::{mpsc, oneshot};
    use futures::StreamExt;
    use http::uri::InvalidUri;
    use http::{Method, StatusCode, Uri, Version};
    use hudsucker::Proxy;
    use std::error::Error;
    use std::fs::File;
    use std::io::{BufReader, Seek, SeekFrom};
    use std::net::{SocketAddr, TcpListener, ToSocketAddrs as _};
    use std::str::from_utf8;
    use std::str::FromStr;
    use tempfile::TempDir;
    use test_common::{http_client, start_http_server, start_https_server};

    struct ProxyInfo {
        addr: SocketAddr,
        // ca_cert: reqwest::Certificate,
        recorded_url_rx: mpsc::Receiver<RecordedUrl>,
        stop_proxy_tx: oneshot::Sender<()>,
    }

    fn start_proxy() -> ProxyInfo {
        let mut path = TempDir::new().unwrap().into_path();
        path.push("test_proxy.pem");
        let tcp_listener =
            TcpListener::bind("localhost:0".to_socket_addrs().unwrap().next().unwrap()).unwrap();
        let addr = tcp_listener.local_addr().unwrap();
        let ca = certauth(&path).unwrap();

        let _ca_cert = {
            let mut f = BufReader::new(File::open(&path).unwrap());
            let der = &rustls_pemfile::certs(&mut f).unwrap()[0];
            reqwest::Certificate::from_der(der).unwrap()
        };

        let (recorded_url_tx, recorded_url_rx) = mpsc::channel::<RecordedUrl>(500);
        let proxy = Proxy::builder()
            .with_listener(tcp_listener)
            .with_client(proxy_client())
            .with_ca(ca)
            .with_http_handler(ProxyTransactionHandler::new(recorded_url_tx))
            .build();

        let (stop_proxy_tx, stop_proxy_rx) = oneshot::channel::<()>();
        tokio::spawn(proxy.start(async {
            stop_proxy_rx.await.unwrap();
            println!("proxy stopped");
        }));

        ProxyInfo {
            addr,
            // ca_cert,
            recorded_url_rx,
            stop_proxy_tx,
        }
    }

    #[tokio::test]
    async fn test_proxy_http_url() -> Result<(), Box<dyn Error>> {
        let mut proxy_info = start_proxy();
        let client = http_client(proxy_info.addr);

        let (addr, _stop_server_tx) = start_http_server();
        let url = format!("http://{:?}/", addr);

        let t0 = Utc::now();
        let _response = client.get(&url).send().await.unwrap();
        let t1 = Utc::now();

        let mut recorded_url = proxy_info.recorded_url_rx.next().await.unwrap();
        assert!(recorded_url.timestamp >= t0 && recorded_url.timestamp <= t1);
        assert_eq!(recorded_url.request_method, Method::GET);
        assert_eq!(recorded_url.request_uri, Uri::from_str(&url)?);
        assert_eq!(recorded_url.request_version, Version::HTTP_11);

        let request_payload_str = {
            recorded_url
                .request_payload
                .payload
                .seek(SeekFrom::Start(0))?;
            std::io::read_to_string(recorded_url.request_payload.payload).unwrap()
        };
        assert_eq!(request_payload_str, "");
        assert_eq!(recorded_url.request_payload.length, 0);
        assert_eq!(
            format!("sha256:{:x}", &recorded_url.request_payload.sha256),
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );

        assert_eq!(recorded_url.response_status, 200);
        let response_payload_str = {
            recorded_url
                .response_payload
                .payload
                .seek(SeekFrom::Start(0))
                .unwrap();
            std::io::read_to_string(recorded_url.response_payload.payload).unwrap()
        };
        assert_eq!(response_payload_str, "http server response body\n");
        assert_eq!(recorded_url.response_status, StatusCode::from_u16(200)?);
        assert_eq!(recorded_url.response_version, Version::HTTP_11);

        assert!(proxy_info.recorded_url_rx.try_next().is_err());

        proxy_info.stop_proxy_tx.send(()).unwrap();

        Ok(())
    }

    #[test_log::test(tokio::test)]
    async fn test_proxy_https_url() -> Result<(), Box<dyn Error>> {
        let mut proxy_info = start_proxy();
        let client = http_client(proxy_info.addr);

        let (addr, _stop_server_tx) = start_https_server().await.unwrap();
        // let url = format!("https://{:?}/", addr); // results in "Illegal SNI hostname received"
        let url = format!("https://localhost:{}/", addr.port());

        let t0 = Utc::now();
        let _response = client.get(&url).send().await.unwrap();
        let t1 = Utc::now();

        let mut recorded_url = proxy_info.recorded_url_rx.next().await.unwrap();
        assert!(recorded_url.timestamp >= t0 && recorded_url.timestamp <= t1);
        assert_eq!(recorded_url.request_method, Method::GET);
        assert_eq!(recorded_url.request_uri, Uri::from_str(&url)?);
        assert_eq!(recorded_url.request_version, Version::HTTP_11);
        let request_payload_str = {
            recorded_url
                .request_payload
                .payload
                .seek(SeekFrom::Start(0))
                .unwrap();
            std::io::read_to_string(recorded_url.request_payload.payload).unwrap()
        };
        assert_eq!(request_payload_str, "");
        assert_eq!(recorded_url.request_payload.length, 0);
        assert_eq!(
            format!("sha256:{:x}", &recorded_url.request_payload.sha256),
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );

        assert_eq!(recorded_url.response_version, Version::HTTP_11);
        assert_eq!(recorded_url.response_status, StatusCode::from_u16(200)?);
        let response_payload_str = {
            recorded_url
                .response_payload
                .payload
                .seek(SeekFrom::Start(0))
                .unwrap();
            std::io::read_to_string(recorded_url.response_payload.payload).unwrap()
        };
        assert_eq!(response_payload_str, "https server response body\n");

        assert!(proxy_info.recorded_url_rx.try_next().is_err());

        proxy_info.stop_proxy_tx.send(()).unwrap();

        Ok(())
    }
}
