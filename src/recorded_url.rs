use chrono::{DateTime, Utc};
use hudsucker::hyper::http::{request, response, HeaderValue};
use hudsucker::hyper::{HeaderMap, Method, StatusCode, Uri, Version};
use sha2::digest::Output;
use sha2::Sha256;
use std::fmt::Debug;
use tempfile::SpooledTempFile;
use warcio::{HttpRequest, HttpResponse, WarcRecord, WarcRecordPayload, WarcRecordType};

#[derive(Debug)]
pub(crate) struct RecordedPayload {
    pub(crate) sha256: Output<Sha256>,
    pub(crate) payload: SpooledTempFile,
    pub(crate) length: u64,
}

#[derive(Debug)]
pub(crate) struct RecordedUrl {
    pub(crate) timestamp: DateTime<Utc>,

    pub(crate) request_method: Method,
    pub(crate) request_uri: Uri,
    pub(crate) request_version: Version,
    pub(crate) request_headers: HeaderMap<HeaderValue>,
    pub(crate) request_payload: RecordedPayload,

    pub(crate) response_status: StatusCode,
    pub(crate) response_version: Version,
    pub(crate) response_headers: HeaderMap<HeaderValue>,
    pub(crate) response_payload: RecordedPayload,
}

impl RecordedUrl {
    pub(crate) fn builder() -> RecordedUrlBuilder {
        RecordedUrlBuilder {
            timestamp: Utc::now(),

            request_method: None,
            request_uri: None,
            request_version: None,
            request_headers: None,
            request_payload: None,

            response_status: None,
            response_version: None,
            response_headers: None,
            response_payload: None,
        }
    }

    fn into_parts(
        self,
    ) -> (
        DateTime<Utc>,
        Method,
        Uri,
        Version,
        HeaderMap<HeaderValue>,
        RecordedPayload,
        StatusCode,
        Version,
        HeaderMap<HeaderValue>,
        RecordedPayload,
    ) {
        (
            self.timestamp,
            self.request_method,
            self.request_uri,
            self.request_version,
            self.request_headers,
            self.request_payload,
            self.response_status,
            self.response_version,
            self.response_headers,
            self.response_payload,
        )
    }
}

#[derive(Debug)]
pub(crate) struct RecordedUrlBuilder {
    timestamp: DateTime<Utc>,

    request_method: Option<Method>,
    request_uri: Option<Uri>,
    request_version: Option<Version>,
    request_headers: Option<HeaderMap<HeaderValue>>,
    request_payload: Option<RecordedPayload>,

    response_status: Option<StatusCode>,
    response_version: Option<Version>,
    response_headers: Option<HeaderMap<HeaderValue>>,
    response_payload: Option<RecordedPayload>,
}

impl RecordedUrlBuilder {
    pub(crate) fn request_parts(mut self, parts: &request::Parts) -> Self {
        // todo: avoid cloning?
        self.request_method = Some(parts.method.clone());
        self.request_uri = Some(parts.uri.clone());
        self.request_version = Some(parts.version);
        self.request_headers = Some(parts.headers.clone());
        self
    }

    pub(crate) fn request_payload(mut self, payload: RecordedPayload) -> Self {
        self.request_payload = Some(payload);
        self
    }

    pub(crate) fn response_parts(mut self, parts: &response::Parts) -> Self {
        self.response_status = Some(parts.status);
        self.response_version = Some(parts.version);
        self.response_headers = Some(parts.headers.clone()); // todo: avoid cloning?
        self
    }

    pub(crate) fn response_payload(mut self, payload: RecordedPayload) -> Self {
        self.response_payload = Some(payload);
        self
    }

    /// Build a RecordedUrl, consuming the builder. `request_parts()`, `request_payload()`,
    /// `response_parts()` and `response_payload()` must have been called, or this method will
    /// panic.
    pub(crate) fn build(self) -> RecordedUrl {
        RecordedUrl {
            timestamp: self.timestamp,

            request_method: self.request_method.unwrap(),
            request_uri: self.request_uri.unwrap(),
            request_version: self.request_version.unwrap(),
            request_headers: self.request_headers.unwrap(),
            request_payload: self.request_payload.unwrap(),

            response_status: self.response_status.unwrap(),
            response_version: self.response_version.unwrap(),
            response_headers: self.response_headers.unwrap(),
            response_payload: self.response_payload.unwrap(),
        }
    }
}

fn response_record(
    uri: &Uri,
    timestamp: DateTime<Utc>,
    request_method: Method,
    response_status: StatusCode,
    response_version: Version,
    response_headers: HeaderMap<HeaderValue>,
    response_payload: RecordedPayload,
) -> WarcRecord<SpooledTempFile> {
    let http_response = HttpResponse::new(
        response_version,
        response_status,
        response_headers,
        response_payload.length,
        response_payload.payload,
    );
    let record_content_length = http_response.length;
    let payload = WarcRecordPayload::HttpResponse(http_response);
    let record = WarcRecord::builder()
        .generate_record_id()
        .method_metadata(request_method)
        .warc_type(WarcRecordType::Response)
        .warc_date(timestamp)
        .warc_target_uri(&uri.to_string().into_bytes())
        // .warc_ip_address
        .warc_payload_digest(format!("sha256:{:x}", &response_payload.sha256).as_bytes())
        .content_type(b"application/http;msgtype=response")
        .content_length(record_content_length)
        .payload(payload)
        .build();
    record
}

fn request_record(
    uri: &Uri,
    timestamp: DateTime<Utc>,
    request_method: Method,
    request_version: Version,
    request_headers: HeaderMap<HeaderValue>,
    request_payload: RecordedPayload,
) -> WarcRecord<SpooledTempFile> {
    let http_request = HttpRequest::new(
        request_method,
        uri,
        request_version,
        request_headers,
        request_payload.length,
        request_payload.payload,
    );
    let record_content_length = http_request.length;
    let payload = WarcRecordPayload::HttpRequest(http_request);
    let record = WarcRecord::builder()
        .generate_record_id()
        .warc_type(WarcRecordType::Request)
        .warc_date(timestamp)
        .warc_target_uri(&uri.to_string().into_bytes())
        .warc_payload_digest(format!("sha256:{:x}", &request_payload.sha256).as_bytes())
        .content_type(b"application/http;msgtype=request")
        .content_length(record_content_length)
        .payload(payload)
        .build();
    record
}

impl From<RecordedUrl> for Vec<WarcRecord<SpooledTempFile>> {
    fn from(recorded_url: RecordedUrl) -> Self {
        let (
            timestamp,
            request_method,
            request_uri,
            request_version,
            request_headers,
            request_payload,
            response_status,
            response_version,
            response_headers,
            response_payload,
        ) = recorded_url.into_parts();

        let mut records: Vec<WarcRecord<SpooledTempFile>> = Vec::new();
        records.push(response_record(
            &request_uri,
            timestamp,
            request_method.clone(),
            response_status,
            response_version,
            response_headers,
            response_payload,
        ));
        records.push(request_record(
            &request_uri,
            timestamp,
            request_method,
            request_version,
            request_headers,
            request_payload,
        ));

        records
    }
}

#[cfg(test)]
mod tests {
    use crate::recorded_url::{RecordedPayload, RecordedUrl};
    use chrono::{SecondsFormat, Utc};
    use http::StatusCode;
    use hudsucker::hyper::http::{request, response};
    use hudsucker::hyper::{Body, Method, Request, Response, Version};
    use sha2::{Digest, Sha256};
    use std::error::Error;
    use std::io::{Cursor, Read, Seek, SeekFrom, Write};
    use std::str::from_utf8;
    use tempfile::SpooledTempFile;
    use warcio::{WarcRecord, WarcRecordWrite as _, WarcWriter};

    fn empty_payload() -> RecordedPayload {
        RecordedPayload {
            payload: SpooledTempFile::new(4),
            sha256: Sha256::new().finalize(),
            length: 0,
        }
    }

    fn is_empty_payload(payload: &mut RecordedPayload) -> bool {
        let mut buf = Vec::<u8>::new();
        payload.payload.seek(SeekFrom::Start(0)).unwrap();
        payload.payload.read_to_end(&mut buf).unwrap();

        buf == b""
            && payload.sha256.as_slice()
                == [
                    227, 176, 196, 66, 152, 252, 28, 20, 154, 251, 244, 200, 153, 111, 185, 36, 39,
                    174, 65, 228, 100, 155, 147, 76, 164, 149, 153, 27, 120, 82, 184, 85,
                ]
            && payload.length == 0
    }

    fn build_payload(content: &[u8]) -> RecordedPayload {
        let mut f = SpooledTempFile::new(500000);
        let mut sha = Sha256::new();
        f.write_all(content).unwrap();
        sha.update(content);
        let length = f.seek(SeekFrom::End(0)).unwrap();
        f.seek(SeekFrom::Start(0)).unwrap();

        RecordedPayload {
            payload: f,
            sha256: sha.finalize(),
            length,
        }
    }

    fn empty_response_parts() -> response::Parts {
        Response::builder()
            .body(Body::from(Vec::<u8>::new()))
            .unwrap()
            .into_parts()
            .0
    }

    fn minimal_request_parts() -> request::Parts {
        Request::builder()
            .uri("https://example.com/")
            .body(Body::from(Vec::<u8>::new()))
            .unwrap()
            .into_parts()
            .0
    }

    #[test]
    fn test_recorded_url_into_parts() -> Result<(), Box<dyn Error>> {
        let t0 = Utc::now();
        let recorded_url = RecordedUrl::builder()
            .request_parts(&minimal_request_parts())
            .request_payload(empty_payload())
            .response_parts(&empty_response_parts())
            .response_payload(empty_payload())
            .build();
        let t1 = Utc::now();

        let (
            timestamp,
            request_method,
            request_uri,
            request_version,
            request_headers,
            mut request_payload,
            response_status,
            response_version,
            response_headers,
            mut response_payload,
        ) = recorded_url.into_parts();
        assert!(timestamp >= t0 && timestamp <= t1);
        assert_eq!(request_method, Method::GET);
        assert_eq!(
            request_uri.to_string(),
            String::from("https://example.com/")
        );
        assert_eq!(request_version, Version::HTTP_11);
        assert!(request_headers.is_empty());
        assert!(is_empty_payload(&mut request_payload));
        assert_eq!(response_status, StatusCode::from_u16(200)?);
        assert_eq!(response_version, Version::HTTP_11);
        assert!(response_headers.is_empty());
        assert!(is_empty_payload(&mut response_payload));
        Ok(())
    }

    /*
    #[test]
    fn test_recorded_url_mimetype() {
        let recorded_url = RecordedUrl::builder()
            .request_parts(&minimal_request_parts())
            .request_payload(empty_payload())
            .response_parts(
                &Response::builder()
                    .header("Content-type", "text/plain; charset=utf-8")
                    .body(Body::from(Vec::<u8>::new()))
                    .unwrap()
                    .into_parts()
                    .0,
            )
            .response_payload(empty_payload())
            .build();
        assert!(recorded_url.mimetype.is_some());
        assert_eq!(recorded_url.mimetype.unwrap(), "text/plain");
    }
     */

    /*
    #[test]
    fn test_recorded_url_request_line() {
        let recorded_url = RecordedUrl::builder()
            .request_parts(
                &Request::builder()
                    .uri("/foo/bar?baz=quux")
                    .method("PATCH")
                    .version(Version::HTTP_10)
                    .body(Body::from(Vec::<u8>::new()))
                    .unwrap()
                    .into_parts()
                    .0,
            )
            .request_payload(empty_payload())
            .response_parts(&empty_response_parts())
            .response_payload(empty_payload())
            .build();
        assert_eq!(
            from_utf8(&recorded_url.request_line).unwrap(),
            "PATCH /foo/bar?baz=quux HTTP/1.0\r\n"
        )
    }
     */

    #[test]
    fn test_recorded_url_request_headers() {
        let recorded_url = RecordedUrl::builder()
            .request_parts(
                &Request::builder()
                    .header("b", "1")
                    .header("Duplicate", "2")
                    .header("a", "3")
                    .header("Duplicate", "4")
                    .header("mUsTaRD", "3")
                    .body(Body::from(Vec::<u8>::new()))
                    .unwrap()
                    .into_parts()
                    .0,
            )
            .request_payload(empty_payload())
            .response_parts(&empty_response_parts())
            .response_payload(empty_payload())
            .build();
        let mut request_headers_iter = recorded_url.request_headers.into_iter();
        assert_eq!(
            request_headers_iter.next(),
            Some((Some("b".parse().unwrap()), "1".parse().unwrap()))
        );
        assert_eq!(
            request_headers_iter.next(),
            Some((Some("duplicate".parse().unwrap()), "2".parse().unwrap()))
        );
        assert_eq!(
            request_headers_iter.next(),
            Some((None, "4".parse().unwrap()))
        );
        assert_eq!(
            request_headers_iter.next(),
            Some((Some("a".parse().unwrap()), "3".parse().unwrap()))
        );
        assert_eq!(
            request_headers_iter.next(),
            Some((Some("mustard".parse().unwrap()), "3".parse().unwrap()))
        );
        assert_eq!(request_headers_iter.next(), None);
    }

    /*
    #[test]
    fn test_recorded_url_response_standard_status() {
        let recorded_url = RecordedUrl::builder()
            .request_parts(&minimal_request_parts())
            .request_payload(empty_payload())
            .response_parts(
                &Response::builder()
                    .status(418)
                    .body(Body::from(Vec::<u8>::new()))
                    .unwrap()
                    .into_parts()
                    .0,
            )
            .response_payload(empty_payload())
            .build();
        assert_eq!(recorded_url.status, 418);
        assert_eq!(
            from_utf8(&recorded_url.response_status_line).unwrap(),
            "HTTP/1.1 418 I'm a teapot\r\n"
        );
    }
     */

    /*
    #[test]
    fn test_recorded_url_response_unknown_status() {
        let recorded_url = RecordedUrl::builder()
            .request_parts(&minimal_request_parts())
            .request_payload(empty_payload())
            .response_parts(
                &Response::builder()
                    // .status("420 Chill bro")
                    .status(420)
                    .body(Body::from(Vec::<u8>::new()))
                    .unwrap()
                    .into_parts()
                    .0,
            )
            .response_payload(empty_payload())
            .build();
        assert_eq!(recorded_url.status, 420);
        assert_eq!(
            from_utf8(&recorded_url.response_status_line).unwrap(),
            "HTTP/1.1 420 No Known Reason\r\n"
        );
    }
     */

    #[test]
    fn test_recorded_url_response_headers() {
        let recorded_url = RecordedUrl::builder()
            .request_parts(&minimal_request_parts())
            .request_payload(empty_payload())
            .response_parts(
                &Response::builder()
                    .header("b", "1")
                    .header("Duplicate", "2")
                    .header("a", "3")
                    .header("Duplicate", "4")
                    .header("mUsTaRD", "3")
                    .body(Body::from(Vec::<u8>::new()))
                    .unwrap()
                    .into_parts()
                    .0,
            )
            .response_payload(empty_payload())
            .build();
        let mut response_headers_iter = recorded_url.response_headers.into_iter();
        assert_eq!(
            response_headers_iter.next(),
            Some((Some("b".parse().unwrap()), "1".parse().unwrap()))
        );
        assert_eq!(
            response_headers_iter.next(),
            Some((Some("duplicate".parse().unwrap()), "2".parse().unwrap()))
        );
        assert_eq!(
            response_headers_iter.next(),
            Some((None, "4".parse().unwrap()))
        );
        assert_eq!(
            response_headers_iter.next(),
            Some((Some("a".parse().unwrap()), "3".parse().unwrap()))
        );
        assert_eq!(
            response_headers_iter.next(),
            Some((Some("mustard".parse().unwrap()), "3".parse().unwrap()))
        );
        assert_eq!(response_headers_iter.next(), None);
    }

    #[test]
    fn test_recorded_url_request_payload() {
        const CONTENT: &[u8; 29] = b"lorem ipsum shmipsum flipsum\n";
        let mut recorded_url = RecordedUrl::builder()
            .request_parts(&minimal_request_parts())
            .request_payload(build_payload(CONTENT))
            .response_parts(&empty_response_parts())
            .response_payload(empty_payload())
            .build();

        let mut buf: Vec<u8> = Vec::new();
        recorded_url
            .request_payload
            .payload
            .read_to_end(&mut buf)
            .unwrap();
        assert_eq!(&buf, CONTENT);
        assert_eq!(recorded_url.request_payload.length, CONTENT.len() as u64);
        assert_eq!(
            recorded_url.request_payload.sha256.as_slice(),
            [
                246, 94, 186, 154, 79, 82, 252, 61, 167, 250, 82, 168, 20, 253, 238, 106, 67, 189,
                113, 181, 176, 115, 30, 22, 154, 215, 237, 184, 111, 66, 248, 111
            ]
        );
    }

    #[test]
    fn test_recorded_url_response_payload() {
        const CONTENT: &[u8; 29] = b"lorem ipsum shmipsum flipsum\n";
        let mut recorded_url = RecordedUrl::builder()
            .request_parts(&minimal_request_parts())
            .request_payload(empty_payload())
            .response_parts(&empty_response_parts())
            .response_payload(build_payload(CONTENT))
            .build();

        let mut buf: Vec<u8> = Vec::new();
        recorded_url
            .response_payload
            .payload
            .read_to_end(&mut buf)
            .unwrap();
        assert_eq!(buf, CONTENT);
        assert_eq!(recorded_url.response_payload.length, CONTENT.len() as u64);
        assert_eq!(
            recorded_url.response_payload.sha256.as_slice(),
            [
                246, 94, 186, 154, 79, 82, 252, 61, 167, 250, 82, 168, 20, 253, 238, 106, 67, 189,
                113, 181, 176, 115, 30, 22, 154, 215, 237, 184, 111, 66, 248, 111
            ]
        );
    }

    #[test]
    fn test_recorded_url_timestamp() {
        let t0 = Utc::now();
        let recorded_url = RecordedUrl::builder()
            .request_parts(&minimal_request_parts())
            .request_payload(empty_payload())
            .response_parts(&empty_response_parts())
            .response_payload(empty_payload())
            .build();
        let t1 = Utc::now();
        assert!(recorded_url.timestamp >= t0 && recorded_url.timestamp <= t1);
    }

    #[test]
    fn test_warc_record_from_recorded_url() -> Result<(), Box<dyn Error>> {
        let recorded_url = RecordedUrl::builder()
            .request_parts(
                &Request::builder()
                    .method("POST")
                    .version(Version::HTTP_3)
                    .header("Howdly", "Doodly dood")
                    .uri("https://example.com/a/b?c=d&e=f")
                    .body(Body::from(Vec::<u8>::new()))
                    .unwrap()
                    .into_parts()
                    .0,
            )
            .request_payload(build_payload(b"I'm your request payload"))
            .response_parts(
                &Response::builder()
                    .version(Version::HTTP_11)
                    .status(418)
                    .header("Requestly", "Headlier")
                    .body(Body::from(Vec::<u8>::new())) // not used
                    .unwrap()
                    .into_parts()
                    .0,
            )
            .response_payload(build_payload(b"I'm your response payload"))
            .build();

        let warc_date = recorded_url
            .timestamp
            .to_rfc3339_opts(SecondsFormat::Micros, true);

        let mut warc_writer = WarcWriter::new(Cursor::new(Vec::<u8>::new()), false);
        let records = Vec::<WarcRecord<SpooledTempFile>>::from(recorded_url);
        let record_ids = records
            .into_iter()
            .map(|record| {
                let warc_record_info = warc_writer.write_record(record, None).unwrap();
                warc_record_info.warc_record_metadata.record_id.unwrap()
            })
            .collect::<Vec<Vec<u8>>>();
        assert_eq!(
            from_utf8(&warc_writer.into_inner().into_inner()).unwrap(),
            format!(
                concat!(
                    "WARC/1.1\r\n",
                    "WARC-Record-ID: <{}>\r\n",
                    "WARC-Type: response\r\n",
                    "WARC-Date: {}\r\n",
                    "WARC-Target-URI: https://example.com/a/b?c=d&e=f\r\n",
                    "WARC-Payload-Digest: sha256:ac0a325a80368e33a0b20f15a9c540a3471b5f6e4d73215b3b963c68b696df11\r\n",
                    "Content-Type: application/http;msgtype=response\r\n",
                    "Content-Length: 75\r\n",
                    "\r\n",
                    "HTTP/1.1 418 I'm a teapot\r\n",
                    "requestly: Headlier\r\n",
                    "\r\n",
                    "I'm your response payload\r\n",
                    "\r\n",
                    "WARC/1.1\r\n",
                    "WARC-Record-ID: <{}>\r\n",
                    "WARC-Type: request\r\n",
                    "WARC-Date: {}\r\n",
                    "WARC-Target-URI: https://example.com/a/b?c=d&e=f\r\n",
                    "WARC-Payload-Digest: sha256:e41aa34eadbd35db1fe0ffabd4750136630de9ac9d66b5a42c71f2518ead5c80\r\n",
                    "Content-Type: application/http;msgtype=request\r\n",
                    "Content-Length: 75\r\n",
                    "\r\n",
                    "POST /a/b?c=d&e=f HTTP/3.0\r\n",
                    "howdly: Doodly dood\r\n",
                    "\r\n",
                    "I'm your request payload\r\n",
                    "\r\n",
                ),
                from_utf8(record_ids.get(0).unwrap())?,
                warc_date,
                from_utf8(record_ids.get(1).unwrap())?,
                warc_date
            )
        );
        Ok(())
    }

    #[test]
    #[should_panic]
    fn test_recorded_url_builder_panics_without_request_parts() {
        RecordedUrl::builder()
            .request_payload(empty_payload())
            .response_parts(&empty_response_parts())
            .response_payload(empty_payload())
            .build();
    }

    #[test]
    #[should_panic]
    fn test_recorded_url_builder_panics_without_request_payload() {
        RecordedUrl::builder()
            .request_parts(&minimal_request_parts())
            .response_parts(&empty_response_parts())
            .response_payload(empty_payload())
            .build();
    }

    #[test]
    #[should_panic]
    fn test_recorded_url_builder_panics_without_response_parts() {
        RecordedUrl::builder()
            .request_parts(&minimal_request_parts())
            .request_payload(empty_payload())
            .response_payload(empty_payload())
            .build();
    }

    #[test]
    #[should_panic]
    fn test_recorded_url_builder_panics_without_response_payload() {
        RecordedUrl::builder()
            .request_parts(&minimal_request_parts())
            .request_payload(empty_payload())
            .response_parts(&empty_response_parts())
            .build();
    }
}
