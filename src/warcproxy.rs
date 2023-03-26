use crate::ca;
use crate::postfetch::Postfetch;
use crate::proxy::ProxyTransactionHandler;
use crate::proxy_client::proxy_client;
use crate::recorded_url::RecordedUrl;
use futures::channel::mpsc;
use futures::try_join;
use hudsucker::certificate_authority::RcgenAuthority;
use hudsucker::hyper::client::HttpConnector;
use hudsucker::{NoopHandler, Proxy};
use hyper_rustls::HttpsConnector;
use std::error::Error;
use std::future::Future;
use std::net::{SocketAddr, TcpListener};
use tokio::task::JoinHandle;

pub struct WarcProxy {
    pub addr: SocketAddr,
    proxy: Option<
        Proxy<HttpsConnector<HttpConnector>, RcgenAuthority, ProxyTransactionHandler, NoopHandler>,
    >,
    postfetch: Option<Postfetch>,
    // recorded_url_rx: mpsc::Receiver<RecordedUrl>,
    // gzip: bool,
    // warc_filename_template: String,
    // port: u16,
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
            proxy: Some(
                Proxy::builder()
                    .with_listener(tcp_listener)
                    .with_client(proxy_client())
                    .with_ca(ca)
                    .with_http_handler(ProxyTransactionHandler::new(recorded_url_tx))
                    .build(),
            ),
            postfetch: Some(Postfetch::new(
                recorded_url_rx,
                warc_filename_template,
                gzip,
                port,
            )),
        })
    }

    /// Returns tuple (proxy_join_handle, postfetch_join_handle). Your code doesn't necessarily
    /// have to do anything with those though. They are useful for tests.
    pub fn spawn<F: Future<Output = ()> + Send + 'static>(
        mut self,
        shutdown_signal: F,
    ) -> (
        JoinHandle<Result<(), hudsucker::Error>>, // proxy join handle
        JoinHandle<Result<(), std::io::Error>>,   // postfetch join handle
    ) {
        (
            tokio::spawn(self.proxy.take().unwrap().start(shutdown_signal)),
            tokio::spawn(self.postfetch.take().unwrap().start(shutdown_signal)),
        )
    }

    /// Spawns proxy and postfetch and waits for them to finish.
    ///
    /// Can return an error from the futures level, or from the proxy, or from postfetch.
    ///
    /// If both postfetch and proxy an error, the proxy error is returned and the postfetch error is
    /// swallowed. Returning both would make the function signature ugly. todo: reevaluate this
    /// decision
    pub async fn run_until_shutdown<F: Future<Output = ()> + Send + 'static>(
        self,
        shutdown_signal: F,
    ) -> Result<(), Box<dyn Error>> {
        let (proxy_join_handle, postfetch_join_handle) = self.spawn(shutdown_signal);
        let (proxy_join_result, postfetch_join_result) =
            try_join!(proxy_join_handle, postfetch_join_handle)?;
        if proxy_join_result.is_err() {
            proxy_join_result.map_err(|e| e.into())
        } else if postfetch_join_result.is_err() {
            postfetch_join_result.map_err(|e| e.into())
        } else {
            Ok(())
        }
    }
}

// todo:
//
#[cfg(test)]
mod tests {
    use crate::WarcProxy;
    use futures::channel::oneshot;
    use futures::FutureExt;
    use std::error::Error;
    use tempfile::NamedTempFile;

    // fn test_new_does_not_start_anything () {}
    // fn test_run_until_shutdown_starts_proxy_and_postfetch() {}

    #[test_log::test(tokio::test)]
    async fn test_shutdown_signal_stops_proxy_and_postfetch() -> Result<(), Box<dyn Error>> {
        let ca_cert = NamedTempFile::new()?.into_temp_path();
        let ca_cert_path = String::from(ca_cert.to_str().unwrap());
        ca_cert.close()?;
        let warcproxy = WarcProxy::new(
            "localhost:0",
            true,
            &ca_cert_path,
            String::from("warcprox-test-{serialno}.warc"),
        )?;

        let (shutdown_oneshot_tx, shutdown_oneshot_rx) = oneshot::channel::<()>();
        let (proxy_join_handle, postfetch_join_handle) =
            warcproxy.spawn(shutdown_oneshot_rx.map(|_| ()));
        shutdown_oneshot_tx.send(()).unwrap();

        // todo: wait with timeout? poll is_finished() with timeout?
        proxy_join_handle.await??;
        postfetch_join_handle.await??;

        Ok(())
    }
}
