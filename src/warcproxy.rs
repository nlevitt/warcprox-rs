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
use std::error::Error;
use std::future::Future;
use std::net::{SocketAddr, TcpListener};

pub struct WarcProxy {
    pub addr: SocketAddr,
    proxy:
        Proxy<HttpsConnector<HttpConnector>, RcgenAuthority, ProxyTransactionHandler, NoopHandler>,
    recorded_url_rx: mpsc::Receiver<RecordedUrl>,
    gzip: bool,
    warc_filename_template: String,
    port: u16,
}

impl WarcProxy {
    pub fn new(
        address: &str,
        gzip: bool,
        ca_cert_path: &str,
        warc_filename_template: String,
    ) -> Result<Self, Box<dyn Error>> {
        let ca = ca::certauth(&ca_cert_path)?;
        let (recorded_url_tx, recorded_url_rx) = mpsc::channel::<RecordedUrl>(500);
        let tcp_listener = TcpListener::bind(address)?;
        let port = tcp_listener.local_addr()?.port();
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
            warc_filename_template,
            port,
        })
    }

    pub async fn run_until_shutdown<F: Future<Output = ()>>(
        self,
        shutdown_signal: F,
    ) -> Result<(), hudsucker::Error> {
        spawn_postfetch(
            self.recorded_url_rx,
            self.gzip,
            self.warc_filename_template,
            self.port,
        );
        self.proxy.start(shutdown_signal).await
    }
}

// todo:
//
// #[cfg(test)]
// mod tests {
//     fn test_new_does_not_start_anything () {}
//     fn test_run_until_shutdown_starts_proxy_and_postfetch() {}
//     fn test_shutdown_signal_stops_proxy_and_postfetch() {}
// }
