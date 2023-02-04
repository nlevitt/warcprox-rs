use futures::channel::oneshot;
use hudsucker::certificate_authority::CertificateAuthority;
use hudsucker::hyper;
use hudsucker::hyper::server::conn::AddrStream;
use hudsucker::hyper::service::{make_service_fn, service_fn};
use std::convert::Infallible;
use std::net::{SocketAddr, TcpListener, ToSocketAddrs as _};
use tempfile::TempDir;
use tls_listener::TlsListener;
use warcprox_rs::certauth;

pub fn start_http_server() -> (SocketAddr, oneshot::Sender<()>) {
    let make_svc = make_service_fn(|_conn: &AddrStream| async {
        Ok::<_, Infallible>(service_fn(|_: hyper::Request<hyper::Body>| async {
            Ok::<_, Infallible>(hyper::Response::new(hyper::Body::from(
                "http server response body\n",
            )))
        }))
    });

    let listener =
        TcpListener::bind("localhost:0".to_socket_addrs().unwrap().next().unwrap()).unwrap();
    let addr = listener.local_addr().unwrap();

    let (stop_server_tx, stop_server_rx) = oneshot::channel::<()>();

    let server = hyper::Server::from_tcp(listener).unwrap();
    let server = server.serve(make_svc);
    let server = server.with_graceful_shutdown(async { stop_server_rx.await.unwrap_or_default() });
    tokio::spawn(server);

    (addr, stop_server_tx)
}

pub async fn start_https_server(
) -> Result<(SocketAddr, oneshot::Sender<()>), Box<dyn std::error::Error>> {
    let mut path = TempDir::new().unwrap().into_path();
    path.push("test_https_server.pem");
    let ca = certauth(&path).unwrap();

    let make_svc = make_service_fn(|_| async {
        Ok::<_, Infallible>(service_fn(|_req: hyper::Request<hyper::Body>| async {
            Ok::<_, Infallible>(hyper::Response::new(hyper::Body::from(
                "https server response body\n",
            )))
        }))
    });

    let listener =
        TcpListener::bind("localhost:0".to_socket_addrs().unwrap().next().unwrap()).unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor: tokio_rustls::TlsAcceptor = ca
        .gen_server_config(&"localhost".parse().unwrap())
        .await
        .into();
    let listener = TlsListener::new(acceptor, tokio::net::TcpListener::from_std(listener)?);

    let (stop_server_tx, stop_server_rx) = oneshot::channel::<()>();

    tokio::spawn(
        hyper::Server::builder(listener)
            .serve(make_svc)
            .with_graceful_shutdown(async { stop_server_rx.await.unwrap_or_default() }),
    );

    Ok((addr, stop_server_tx))
}

pub fn http_client(proxy_addr: SocketAddr) -> reqwest::Client {
    let proxy_url = format!("http://{:?}", proxy_addr);
    reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(proxy_url).unwrap())
        // .add_root_certificate(proxy_info.ca_cert) // FIXME not working
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap()
}
