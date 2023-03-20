use hudsucker::hyper::client::HttpConnector;
use hudsucker::hyper::Client;
use rustls::client::{ServerCertVerified, ServerCertVerifier};
use rustls::{Certificate, Error, ServerName};
use std::sync::Arc;
use std::time::SystemTime;

struct AllTrustingCertificateVerifier;

impl ServerCertVerifier for AllTrustingCertificateVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &Certificate,
        _intermediates: &[Certificate],
        _server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: SystemTime,
    ) -> Result<ServerCertVerified, Error> {
        // todo: do normal cert verification and just warn about it
        // and record the cert info for saving to warc
        Ok(ServerCertVerified::assertion())
    }
}

pub fn proxy_client() -> Client<hyper_rustls::HttpsConnector<HttpConnector>> {
    Client::builder()
        .http1_title_case_headers(true)
        .http1_preserve_header_case(true)
        .build(
            hyper_rustls::HttpsConnectorBuilder::new()
                .with_tls_config(
                    rustls::ClientConfig::builder()
                        .with_safe_defaults()
                        .with_custom_certificate_verifier(Arc::new(
                            AllTrustingCertificateVerifier {},
                        ))
                        .with_no_client_auth(),
                )
                .https_or_http()
                .enable_http1()
                .build(),
        )
}

#[cfg(test)]
mod tests {
    use crate::proxy_client::proxy_client;
    use http::{StatusCode, Uri};
    use std::error::Error;
    use test_common::start_https_server;

    #[test_log::test(tokio::test)]
    async fn test_proxy_client_trusts_any_certificate() -> Result<(), Box<dyn Error>> {
        let (addr, _stop_server_tx) = start_https_server().await?;
        let cli = proxy_client();
        let url = Uri::builder()
            .scheme("https")
            .authority(format!("localhost:{}", addr.port()))
            .path_and_query("/")
            .build()?;
        let response = cli.get(url).await;
        assert!(response.is_ok());
        assert_eq!(response?.status(), StatusCode::OK);
        Ok(())
    }
}
