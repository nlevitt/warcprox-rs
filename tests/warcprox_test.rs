use futures::channel::oneshot;
use futures::FutureExt as _;
use tempfile::NamedTempFile;
use test_common::{http_client, start_http_server, start_https_server};
use warcprox_rs::WarcProxy;

#[test_log::test(tokio::test)]
async fn test_foo() {
    let (_http_addr, _http_stop_server_tx) = start_http_server();
    let (https_addr, _https_stop_server_tx) = start_https_server().await.unwrap();
    let ca_cert = NamedTempFile::new().unwrap().into_temp_path();
    let ca_cert_path = String::from(ca_cert.to_str().unwrap());
    ca_cert.close().unwrap();
    let warcproxy = WarcProxy::new("localhost:0", false, &ca_cert_path).unwrap();

    let http_client = http_client(warcproxy.addr);

    let (_shutdown_oneshot_tx, shutdown_oneshot_rx) = oneshot::channel::<()>();
    tokio::spawn(warcproxy.run_until_shutdown(shutdown_oneshot_rx.map(|_| ())));

    let url = format!("https://localhost:{}/", https_addr.port());
    let response = http_client.get(&url).send().await.unwrap();
    assert_eq!(response.status(), 200);
}
