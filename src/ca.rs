use hudsucker::{certificate_authority::RcgenAuthority, rustls};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType, DnValue, IsCa,
};
use std::fs::File;
use std::io::{BufReader, Write};
use std::path::Path;
use tracing::info;

pub fn create_ca(path: &str) -> Result<RcgenAuthority, Box<dyn std::error::Error>> {
    info!("creating CA cert {}", path);
    let mut ca_cert_params = CertificateParams::default();
    ca_cert_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    ca_cert_params.distinguished_name = DistinguishedName::new();
    ca_cert_params.distinguished_name.push(
        DnType::CommonName,
        DnValue::PrintableString("warcprox-rs CA".to_string()),
    );
    let ca_cert = Certificate::from_params(ca_cert_params).unwrap();

    let mut f = File::create(path)?;
    f.write(ca_cert.get_key_pair().serialize_pem().as_bytes())?;
    f.write(ca_cert.serialize_pem()?.as_bytes())?;

    let private_key = rustls::PrivateKey(ca_cert.get_key_pair().serialize_der());
    let ca_cert = rustls::Certificate(ca_cert.serialize_der().unwrap());

    let ca = RcgenAuthority::new(private_key, ca_cert, 10_000)
        .expect("failed to create certificate authority");
    Ok(ca)
}

fn load_ca(path: &String) -> Result<RcgenAuthority, Box<dyn std::error::Error>> {
    info!("loading CA cert {}", path);
    let mut f = BufReader::new(File::open(&path)?);
    let mut key: Option<Vec<u8>> = None;
    let mut cert: Option<Vec<u8>> = None;
    for item in std::iter::from_fn(|| rustls_pemfile::read_one(&mut f).transpose()) {
        match item.unwrap() {
            rustls_pemfile::Item::X509Certificate(c) => {
                cert = Some(c);
                if key.is_some() {
                    break;
                }
            }
            rustls_pemfile::Item::RSAKey(k) => {
                key = Some(k);
                if cert.is_some() {
                    break;
                }
            }
            rustls_pemfile::Item::PKCS8Key(k) => {
                key = Some(k);
                if cert.is_some() {
                    break;
                }
            }
            rustls_pemfile::Item::ECKey(k) => {
                key = Some(k);
                if cert.is_some() {
                    break;
                }
            }
            _ => {}
        }
    }
    if key.is_none() {
        panic!("private key not found in {}", path)
    }
    if cert.is_none() {
        panic!("certificate not found in {}", path)
    }
    let ca = RcgenAuthority::new(
        rustls::PrivateKey(key.take().unwrap()),
        rustls::Certificate(cert.take().unwrap()),
        10_000,
    )
    .expect(&format!(
        "failed to set up certificate authority from key and cert loaded from {}",
        path
    ));
    Ok(ca)
}

pub fn certauth(path: String) -> Result<RcgenAuthority, Box<dyn std::error::Error>> {
    if Path::new(&path).exists() {
        load_ca(&path)
    } else {
        create_ca(&path)
    }
}
