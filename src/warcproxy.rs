use crate::ca;
use crate::postfetch::spawn_postfetch;
use crate::proxy::ProxyTransactionHandler;
use crate::proxy_client::proxy_client;
use crate::recorded_url::RecordedUrl;
use futures::channel::mpsc;
use hudsucker::certificate_authority::RcgenAuthority;
use hudsucker::hyper::client::HttpConnector;
use hudsucker::{NoopHandler, Proxy};
use hyper_rustls::HttpsConnector;
use std::future::Future;
use std::net::{SocketAddr, TcpListener};

pub struct WarcProxy {
    proxy:
        Proxy<HttpsConnector<HttpConnector>, RcgenAuthority, ProxyTransactionHandler, NoopHandler>,
    recorded_url_rx: mpsc::Receiver<RecordedUrl>,
    gzip: bool,
    pub addr: SocketAddr,
}

impl WarcProxy {
    pub fn new(
        address: &str,
        gzip: bool,
        ca_cert_path: &str,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let ca = ca::certauth(&ca_cert_path)?;
        let (recorded_url_tx, recorded_url_rx) = mpsc::channel::<RecordedUrl>(500);
        let tcp_listener = TcpListener::bind(address)?;
        Ok(Self {
            addr: tcp_listener.local_addr()?,
            proxy: Proxy::builder()
                .with_listener(tcp_listener)
                .with_client(proxy_client())
                .with_ca(ca)
                .with_http_handler(ProxyTransactionHandler::new(recorded_url_tx))
                .build(),
            recorded_url_rx,
            gzip,
        })
    }

    pub async fn run_until_shutdown<F: Future<Output = ()>>(
        self,
        shutdown_signal: F,
    ) -> Result<(), hudsucker::Error> {
        spawn_postfetch(self.recorded_url_rx, self.gzip);
        self.proxy.start(shutdown_signal).await
    }
}
