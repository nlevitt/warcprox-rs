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

fn load_ca(path: &str) -> Result<RcgenAuthority, Box<dyn std::error::Error>> {
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

pub fn certauth(path: &str) -> Result<RcgenAuthority, Box<dyn std::error::Error>> {
    if Path::new(&path).exists() {
        load_ca(path)
    } else {
        create_ca(path)
    }
}

#[cfg(test)]
mod tests {
    use crate::ca::certauth;
    use std::fs;
    use std::io::Write;
    use tempfile::{NamedTempFile, TempDir};

    #[test]
    fn test_new_ca() {
        let mut path = TempDir::new().unwrap().into_path();
        path.push("test_round_trip.pem");
        assert!(!path.exists());
        let path = path.to_str().unwrap();
        let created_ca = certauth(path);
        assert!(created_ca.is_ok());
        assert!(fs::metadata(path).unwrap().len() > 0);
    }

    #[test]
    fn test_load_ca() {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(
            concat!(
                // this key/cert pair was created by `create_ca` above
                "-----BEGIN CERTIFICATE-----\n",
                "MIIBYDCCAQagAwIBAgIJALJCtzjuOwt0MAoGCCqGSM49BAMCMBkxFzAVBgNVBAMT\n",
                "DndhcmNwcm94LXJzIENBMCAXDTc1MDEwMTAwMDAwMFoYDzQwOTYwMTAxMDAwMDAw\n",
                "WjAZMRcwFQYDVQQDEw53YXJjcHJveC1ycyBDQTBZMBMGByqGSM49AgEGCCqGSM49\n",
                "AwEHA0IABGi4SNpjZgxz/2VMhjVfturn6BWbkjB5d2a6ek+8SSw/joIVB27VboX4\n",
                "0U6GcopY0SBGb/h/uGWfmQ3P/t/FI3mjNTAzMB0GA1UdDgQWBBR0CzvuOLdCsrDe\n",
                "/KPL/05f1KjCgDASBgNVHRMBAf8ECDAGAQH/AgEAMAoGCCqGSM49BAMCA0gAMEUC\n",
                "IQDNcaT5ovhLANovEThlzCINFpohMB1axy3a8UwRHKYDlQIgRRGqZ6pLVSkrKeGV\n",
                "hHjoJq1RFz/A7X5YXZPlTywOjeA=\n",
                "-----END CERTIFICATE-----\n",
                "-----BEGIN PRIVATE KEY-----\n",
                "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgF5CX4hTeJTxkDPur\n",
                "nOG1Kzl6KoNRYhPXUyduwnKHePGhRANCAARouEjaY2YMc/9lTIY1X7bq5+gVm5Iw\n",
                "eXdmunpPvEksP46CFQdu1W6F+NFOhnKKWNEgRm/4f7hln5kNz/7fxSN5\n",
                "-----END PRIVATE KEY-----\n",
            )
            .as_bytes(),
        )
        .unwrap();

        let ca = certauth(f.path().to_str().unwrap());
        assert!(ca.is_ok());
    }

    #[test]
    fn test_round_trip() {
        let mut path = TempDir::new().unwrap().into_path();
        path.push("test_round_trip.pem");
        assert!(!path.exists());
        let path = path.to_str().unwrap();
        let created_ca = certauth(path);
        assert!(created_ca.is_ok());

        let loaded_ca = certauth(path);
        assert!(loaded_ca.is_ok());
    }

    #[test]
    fn test_warcprox_ca() {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(
            concat!(
                // this key/cert pair was created by python warcprox
                "-----BEGIN PRIVATE KEY-----\n",
                "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDAKMWv7MzbsuW9\n",
                "P2WshMgfAmG+X5Rt5MArubQ2vgVQgfXOEPaj0E6W/9+1FhBRZzFztfR/gACLzIIS\n",
                "K0y+3zQtcQ0kcKu5bvHFlSTDpzcismwHEHby9O7/KTrH47SAww9PCSLt2TERmIEY\n",
                "yKC/m6wM2ENx78Fs3BvAFDCtcDtoPL/S+rA9TLa+bSFIfGm753QOlSAOGcmLTHku\n",
                "UviyVg8ZUn+lVIKEOWh/U8MAu27CDDuH1mWQZ5rIR8LchIYGjrfVa6c2K7cFf+H+\n",
                "gkFfY4e5mGymscY3ACqqZF3Fx1l9qH4ez7PQIlaUJAXYZ/99IT34iK7Yvjj16coD\n",
                "e5tiEw9tAgMBAAECggEAA773uu976d+BrNqxcyIZMEjmBLr3xDGp+7WQeWMNwaKa\n",
                "8FldJCyMJP5Cyz9YHOzM+74Pu17l2Sko3aJO9MdEojXP5VvgmR+Rd9d/DTpeBTTj\n",
                "DWXehRYjGkHLQHjO/MCbXzV6IxaxZxqo5PBfo9nsyh5QKEaIfS8IR8piTYtAeTkc\n",
                "nPXb3nB6GlgCMtJ2SXznhIxCuEAykoqPLglanIqEqIBVgiy3VGbOiiDYZFkUy6FE\n",
                "p+ehO5c4SufMXxhTgU9cJM0g5QOqdl9vwmNB9s8EafsUQnI/jTujdHvpC8w16tC/\n",
                "gTG5tpr09pYxIURzglwzmah6pKHr1M8mpMYErf49QQKBgQDudlhVh4mKh3zn0fFp\n",
                "yVF06jwaz+Oes1FT9zUpOZov7BTUck0AilkgyMjgF81EVvNt5Q6xxGUaI3yrqIpK\n",
                "BaqBSlW5lNYEHNiedqOBa+8yr+ZVlYioQNzladX7Ha1bKONlALKGSvrQddN1a44J\n",
                "ZgV2i8pxSwmUaXEWgcsigzbarQKBgQDOSqfmIVipxVW9slLfOqrEn9eFwAGrlsgW\n",
                "jUFyt61BG5NlMuJWL8Ahll8ZgfU7011GfwFiO236kMVKfORsVYuBPEQGrqoc5rQH\n",
                "M7UzdK97j53WTmy6ejc8vrRiaiIZYIJO2OdpVWWYE7JsGRxDtTcBR1tPYa0ixjen\n",
                "jJPYGRpfwQKBgQCZMv7dNA5xKUpdxMtMI0Jp0nJ650RdGOcPAqrsqU0drJZVRnmh\n",
                "9z/7iANFtQTy+sm5uIcQPhSWDmZyAf2WQL2iApfAepZkXgPtCltRMn6iGc/o/ACn\n",
                "18QSv0Px6McO4d31bdVD4bfxZUFNFqRR9XFdD8IntwWYi4VT6F8Q9SuwoQKBgEHn\n",
                "VdZOZu3tziOJObJ5Ip8oVYk0OxRfWlLiE7ubdG0taxxUcjyIir/wMzeJ7heLwevI\n",
                "nV+NjugSogTW+36koanK4AymdlA/X9pBKa1jpMA7tHgHm/LDIqx0XFpof7ZNv7OC\n",
                "1gMvtgIsoL6qEv6KgSUWb9RfZxmJ67PKVF0gP+3BAoGAczTZzrJMfjfB5nBBBdgD\n",
                "2ua7Jp+KKHHsLHrCNBFF/a2ktIAHUSym2fL9bFeCsLheh5zHBL8kWxNFV12s2MMN\n",
                "6cHIehJRmeHDMbZVmb/0p4+GzrO0rNGt2LFJKOu5xkPLel5rYYlqVF4ls7QPmwpS\n",
                "0pVDOItJLfvgR7Ne3huG38I=\n",
                "-----END PRIVATE KEY-----\n",
                "-----BEGIN CERTIFICATE-----\n",
                "MIIDKjCCAhKgAwIBAgIJAIHLEMs/x8mwMA0GCSqGSIb3DQEBCwUAMDExLzAtBgNV\n",
                "BAMMJldhcmNwcm94IENBIG9uIE1MLW5sZXZpdHQtQzAyREwxNUxNRDZSMB4XDTIy\n",
                "MTIxMjAzMTIxOFoXDTI1MTIxMTAzMTIxOFowMTEvMC0GA1UEAwwmV2FyY3Byb3gg\n",
                "Q0Egb24gTUwtbmxldml0dC1DMDJETDE1TE1ENlIwggEiMA0GCSqGSIb3DQEBAQUA\n",
                "A4IBDwAwggEKAoIBAQDAKMWv7MzbsuW9P2WshMgfAmG+X5Rt5MArubQ2vgVQgfXO\n",
                "EPaj0E6W/9+1FhBRZzFztfR/gACLzIISK0y+3zQtcQ0kcKu5bvHFlSTDpzcismwH\n",
                "EHby9O7/KTrH47SAww9PCSLt2TERmIEYyKC/m6wM2ENx78Fs3BvAFDCtcDtoPL/S\n",
                "+rA9TLa+bSFIfGm753QOlSAOGcmLTHkuUviyVg8ZUn+lVIKEOWh/U8MAu27CDDuH\n",
                "1mWQZ5rIR8LchIYGjrfVa6c2K7cFf+H+gkFfY4e5mGymscY3ACqqZF3Fx1l9qH4e\n",
                "z7PQIlaUJAXYZ/99IT34iK7Yvjj16coDe5tiEw9tAgMBAAGjRTBDMBIGA1UdEwEB\n",
                "/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBTf78TyOjVMJazv\n",
                "WuYSvPPAH68eTzANBgkqhkiG9w0BAQsFAAOCAQEAV42rKBMMyzjGCvB03VrMMCsD\n",
                "SD6pqHPsl3bqBkayWTsIS2y6pWIdJzJ9/tsnX9YkvoEXgdMsmULiVoWhFRTEWenG\n",
                "xw8Mh3GY4oE03Ye9PWq0y5xtQbTpNqABcXvNMVVU3MHvhPe8DZqU97zi69+vef8u\n",
                "urWCMHGJSAnQNhhJIMh2yalvyRAa6tG/NZw4QPP33yFvMTbkD6gYlNlSo5JiQOOc\n",
                "axvzF7SnOmUDUqmPrJJZzSFzELNtPul3czGS3Xc9yX36+gt5Wty9LlC+7VK6+ymN\n",
                "xG5gJx99W+JW7mZoH1WGbSKeWWsskXrS1KN9CDib3hhxg/jJd0IIoR1dHitvlw==\n",
                "-----END CERTIFICATE-----\n",
            )
            .as_bytes(),
        )
        .unwrap();

        let ca = certauth(f.path().to_str().unwrap());
        assert!(ca.is_ok());
    }
}
