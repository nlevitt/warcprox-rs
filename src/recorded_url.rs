use chrono::{DateTime, Utc};
use hudsucker::hyper::http::{request, response};
use hudsucker::hyper::HeaderMap;
use sha2::digest::Output;
use sha2::Sha256;
use std::io::{Cursor, Read};
use tempfile::SpooledTempFile;
use warcio::{WarcRecord, WarcRecordType};

#[derive(Debug)]
pub(crate) struct Payload {
    pub(crate) sha256: Output<Sha256>,
    pub(crate) payload: SpooledTempFile,
    pub(crate) length: usize,
}

#[derive(Debug)]
pub(crate) struct RecordedUrl {
    pub(crate) timestamp: DateTime<Utc>,

    pub(crate) uri: String,
    pub(crate) status: u16,
    pub(crate) method: String,
    pub(crate) mimetype: Option<String>,

    pub(crate) request_line: Vec<u8>,
    pub(crate) request_headers: Vec<u8>,
    pub(crate) request_payload: Payload,
    pub(crate) response_status_line: Vec<u8>,
    pub(crate) response_headers: Vec<u8>,
    pub(crate) response_payload: Payload,
}

impl RecordedUrl {
    pub(crate) fn builder(uri: String) -> RecordedUrlBuilder {
        RecordedUrlBuilder {
            timestamp: Utc::now(),
            uri,
            method: None,
            request_line: None,
            request_headers: None,
            request_payload: None,
            status: None,
            mimetype: None,
            response_status_line: None,
            response_headers: None,
            response_payload: None,
        }
    }

    fn into_parts(
        self,
    ) -> (
        String,
        DateTime<Utc>,
        Vec<u8>,
        Vec<u8>,
        Payload,
        Vec<u8>,
        Vec<u8>,
        Payload,
    ) {
        (
            self.uri,
            self.timestamp,
            self.request_line,
            self.request_headers,
            self.request_payload,
            self.response_status_line,
            self.response_headers,
            self.response_payload,
        )
    }
}

fn request_line_as_bytes(parts: &request::Parts) -> Vec<u8> {
    Vec::from(
        format!(
            "{} {} {:?}\r\n",
            parts.method,
            parts.uri.path_and_query().unwrap(),
            parts.version
        )
        .as_bytes(),
    )
}

fn response_status_line_as_bytes(parts: &response::Parts) -> Vec<u8> {
    Vec::from(
        format!(
            "{:?} {} {}\r\n",
            parts.version,
            parts.status.as_u16(),
            parts
                .status
                .canonical_reason()
                .or(Some("No Known Reason"))
                .unwrap()
        )
        .as_bytes(),
    )
}

fn headers_as_bytes(headers: &HeaderMap) -> Vec<u8> {
    let mut buf = Vec::new();
    for (name, value) in headers {
        buf.extend_from_slice(name.as_str().as_bytes());
        buf.extend_from_slice(b": ");
        buf.extend_from_slice(value.as_bytes());
        buf.extend_from_slice(b"\r\n");
    }
    buf
}

#[derive(Debug)]
pub(crate) struct RecordedUrlBuilder {
    uri: String,
    timestamp: DateTime<Utc>,

    // request stuff
    method: Option<String>,
    request_line: Option<Vec<u8>>,
    request_headers: Option<Vec<u8>>,
    request_payload: Option<Payload>,

    // response stuff
    status: Option<u16>,
    mimetype: Option<String>,
    response_status_line: Option<Vec<u8>>,
    response_headers: Option<Vec<u8>>,
    response_payload: Option<Payload>,
}

impl RecordedUrlBuilder {
    pub(crate) fn request_parts(mut self, parts: &request::Parts) -> Self {
        self.method = Some(parts.method.to_string());
        self.request_line = Some(request_line_as_bytes(parts));
        self.request_headers = Some(headers_as_bytes(&parts.headers));
        self
    }

    pub(crate) fn request_payload(mut self, payload: Payload) -> Self {
        self.request_payload = Some(payload);
        self
    }

    pub(crate) fn response_parts(mut self, parts: &response::Parts) -> Self {
        if let Some(content_type) = parts.headers.get("content-type") {
            if let Ok(content_type) = content_type.to_str() {
                if let Some(semicolon_offset) = content_type.find(';') {
                    self.mimetype = Some(String::from(&content_type[..semicolon_offset]));
                } else {
                    self.mimetype = Some(String::from(content_type));
                }
            }
        }
        self.response_status_line = Some(response_status_line_as_bytes(parts));
        self.response_headers = Some(headers_as_bytes(&parts.headers));
        self.status = Some(u16::from(parts.status));
        self
    }

    pub(crate) fn response_payload(mut self, payload: Payload) -> Self {
        self.response_payload = Some(payload);
        self
    }

    /// Build a RecordedUrl, consuming the builder. `request_parts()`, `request_payload()`,
    /// `response_parts()` and `response_payload()` must have been called, or this method will
    /// panic.
    pub(crate) fn build(mut self) -> RecordedUrl {
        RecordedUrl {
            timestamp: self.timestamp,
            uri: self.uri,
            method: self.method.take().unwrap(),
            request_line: self.request_line.take().unwrap(),
            request_headers: self.request_headers.take().unwrap(),
            request_payload: self.request_payload.take().unwrap(),
            status: self.status.take().unwrap(),
            mimetype: self.mimetype.take(),
            response_status_line: self.response_status_line.take().unwrap(),
            response_headers: self.response_headers.take().unwrap(),
            response_payload: self.response_payload.take().unwrap(),
        }
    }
}

fn response_record(
    uri: &String,
    timestamp: DateTime<Utc>,
    response_status_line: Vec<u8>,
    response_headers: Vec<u8>,
    response_payload: Payload,
) -> WarcRecord<Box<dyn Read>> {
    let full_http_response_length: usize =
        response_status_line.len() + response_headers.len() + 2 + response_payload.length;
    let full_http_response: Box<dyn Read> = Box::new(
        Cursor::new(response_status_line)
            .chain(Cursor::new(response_headers))
            .chain(&b"\r\n"[..])
            .chain(response_payload.payload),
    );

    let record = WarcRecord::builder()
        .generate_record_id()
        .warc_type(WarcRecordType::Response)
        .warc_date(timestamp)
        .warc_target_uri(uri.as_bytes())
        // .warc_ip_address
        .warc_payload_digest(format!("sha256:{:x}", &response_payload.sha256).as_bytes())
        .content_type(b"application/http;msgtype=response")
        .content_length(full_http_response_length)
        .body(full_http_response)
        .build();
    record
}

fn request_record(
    uri: &String,
    timestamp: DateTime<Utc>,
    request_line: Vec<u8>,
    request_headers: Vec<u8>,
    request_payload: Payload,
) -> WarcRecord<Box<dyn Read>> {
    let full_http_request_length: usize =
        request_line.len() + request_headers.len() + 2 + request_payload.length;
    let full_http_request: Box<dyn Read> = Box::new(
        Cursor::new(request_line)
            .chain(Cursor::new(request_headers))
            .chain(&b"\r\n"[..])
            .chain(request_payload.payload),
    );

    let record = WarcRecord::builder()
        .generate_record_id()
        .warc_type(WarcRecordType::Request)
        .warc_date(timestamp)
        .warc_target_uri(uri.as_bytes())
        // .warc_ip_address
        .warc_payload_digest(format!("sha256:{:x}", &request_payload.sha256).as_bytes())
        .content_type(b"application/http;msgtype=request")
        .content_length(full_http_request_length)
        .body(full_http_request)
        .build();
    record
}

impl From<RecordedUrl> for Vec<WarcRecord<Box<dyn Read>>> {
    fn from(recorded_url: RecordedUrl) -> Self {
        let (
            uri,
            timestamp,
            request_line,
            request_headers,
            request_payload,
            response_status_line,
            response_headers,
            response_payload,
        ) = recorded_url.into_parts();

        let mut records: Vec<WarcRecord<Box<dyn Read>>> = Vec::new();
        records.push(response_record(
            &uri,
            timestamp,
            response_status_line,
            response_headers,
            response_payload,
        ));
        records.push(request_record(
            &uri,
            timestamp,
            request_line,
            request_headers,
            request_payload,
        ));

        records
    }
}

#[cfg(test)]
mod tests {
    use crate::recorded_url::{Payload, RecordedUrl};
    use chrono::{SecondsFormat, Utc};
    use hudsucker::hyper::http::{request, response};
    use hudsucker::hyper::{Body, Request, Response, Version};
    use sha2::{Digest, Sha256};
    use std::io::{Cursor, Read, Seek, SeekFrom, Write};
    use std::str::from_utf8;
    use tempfile::SpooledTempFile;
    use warcio::{WarcRecord, WarcWriter};

    fn empty_payload() -> Payload {
        Payload {
            payload: SpooledTempFile::new(4),
            sha256: Sha256::new().finalize(),
            length: 0,
        }
    }

    fn is_empty_payload(payload: &mut Payload) -> bool {
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

    fn build_payload(content: &[u8]) -> Payload {
        let mut f = SpooledTempFile::new(500000);
        let mut sha = Sha256::new();
        f.write_all(content).unwrap();
        sha.update(content);
        let length = f.seek(SeekFrom::End(0)).unwrap() as usize;
        f.seek(SeekFrom::Start(0)).unwrap();

        Payload {
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

    fn empty_request_parts() -> request::Parts {
        Request::builder()
            .body(Body::from(Vec::<u8>::new()))
            .unwrap()
            .into_parts()
            .0
    }

    #[test]
    fn test_recorded_url_into_parts() {
        let t0 = Utc::now();
        let recorded_url = RecordedUrl::builder(String::from("https://example.com/"))
            .request_parts(&empty_request_parts())
            .request_payload(empty_payload())
            .response_parts(&empty_response_parts())
            .response_payload(empty_payload())
            .build();
        let t1 = Utc::now();

        let (
            uri,
            timestamp,
            request_line,
            request_headers,
            mut request_payload,
            response_status_line,
            response_headers,
            mut response_payload,
        ) = recorded_url.into_parts();
        assert_eq!(uri, String::from("https://example.com/"));
        assert!(timestamp >= t0 && timestamp <= t1);
        assert_eq!(from_utf8(&request_line).unwrap(), "GET / HTTP/1.1\r\n");
        assert_eq!(from_utf8(&request_headers).unwrap(), "");
        assert!(is_empty_payload(&mut request_payload));
        assert_eq!(
            from_utf8(&response_status_line).unwrap(),
            "HTTP/1.1 200 OK\r\n"
        );
        assert_eq!(from_utf8(&response_headers).unwrap(), "");
        assert!(is_empty_payload(&mut response_payload));
    }

    #[test]
    fn test_recorded_url_mimetype() {
        let recorded_url = RecordedUrl::builder(String::from("https://example.com/"))
            .request_parts(&empty_request_parts())
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

    #[test]
    fn test_recorded_url_request_line() {
        let recorded_url = RecordedUrl::builder(String::from("https://example.com/"))
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

    #[test]
    fn test_recorded_url_request_headers() {
        let recorded_url = RecordedUrl::builder(String::from("https://example.com/"))
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
        assert_eq!(
            from_utf8(&recorded_url.request_headers).unwrap(),
            concat!(
                "b: 1\r\n",
                "duplicate: 2\r\n",
                "duplicate: 4\r\n",
                "a: 3\r\n",
                "mustard: 3\r\n"
            )
        )
    }

    #[test]
    fn test_recorded_url_response_standard_status() {
        let recorded_url = RecordedUrl::builder(String::from("https://example.com/"))
            .request_parts(&empty_request_parts())
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

    #[test]
    fn test_recorded_url_response_unknown_status() {
        let recorded_url = RecordedUrl::builder(String::from("https://example.com/"))
            .request_parts(&empty_request_parts())
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

    #[test]
    fn test_recorded_url_response_headers() {
        let recorded_url = RecordedUrl::builder(String::from("https://example.com/"))
            .request_parts(&empty_request_parts())
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
        assert_eq!(
            from_utf8(&recorded_url.response_headers).unwrap(),
            concat!(
                "b: 1\r\n",
                "duplicate: 2\r\n",
                "duplicate: 4\r\n",
                "a: 3\r\n",
                "mustard: 3\r\n"
            )
        )
    }

    #[test]
    fn test_recorded_url_request_payload() {
        const CONTENT: &[u8; 29] = b"lorem ipsum shmipsum flipsum\n";
        let mut recorded_url = RecordedUrl::builder(String::from("https://example.com/"))
            .request_parts(&empty_request_parts())
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
        assert_eq!(recorded_url.request_payload.length, CONTENT.len());
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
        let mut recorded_url = RecordedUrl::builder(String::from("https://example.com/"))
            .request_parts(&empty_request_parts())
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
        assert_eq!(recorded_url.response_payload.length, CONTENT.len());
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
        let recorded_url = RecordedUrl::builder(String::from("https://example.com/"))
            .request_parts(&empty_request_parts())
            .request_payload(empty_payload())
            .response_parts(&empty_response_parts())
            .response_payload(empty_payload())
            .build();
        let t1 = Utc::now();
        assert!(recorded_url.timestamp >= t0 && recorded_url.timestamp <= t1);
    }

    #[test]
    fn test_warc_record_from_recorded_url() {
        let recorded_url = RecordedUrl::builder(String::from("https://example.com/"))
            .request_parts(
                &Request::builder()
                    .method("POST")
                    .version(Version::HTTP_3)
                    .header("Howdly", "Doodly dood")
                    .uri("/a/b?c=d&e=f")
                    .body(Body::from(Vec::<u8>::new())) // not used
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
        let records = Vec::<WarcRecord<Box<dyn Read>>>::from(recorded_url);
        let (record_id_0, record_id_1) =
            (records[0].record_id.clone(), records[1].record_id.clone());
        for record in records {
            warc_writer.write_record(record).unwrap();
        }
        assert_eq!(
            from_utf8(&warc_writer.into_inner().into_inner()).unwrap(),
            format!(
                concat!(
                    "WARC/1.1\r\n",
                    "WARC-Record-ID: <{}>\r\n",
                    "WARC-Type: response\r\n",
                    "WARC-Date: {}\r\n",
                    "WARC-Target-URI: https://example.com/\r\n",
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
                    "WARC-Target-URI: https://example.com/\r\n",
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
                record_id_0,
                warc_date,
                record_id_1,
                warc_date
            )
        );
    }

    #[test]
    #[should_panic]
    fn test_recorded_url_builder_panics_without_request_parts() {
        RecordedUrl::builder(String::from("https://example.com/"))
            .request_payload(empty_payload())
            .response_parts(&empty_response_parts())
            .response_payload(empty_payload())
            .build();
    }

    #[test]
    #[should_panic]
    fn test_recorded_url_builder_panics_without_request_payload() {
        RecordedUrl::builder(String::from("https://example.com/"))
            .request_parts(&empty_request_parts())
            .response_parts(&empty_response_parts())
            .response_payload(empty_payload())
            .build();
    }

    #[test]
    #[should_panic]
    fn test_recorded_url_builder_panics_without_response_parts() {
        RecordedUrl::builder(String::from("https://example.com/"))
            .request_parts(&empty_request_parts())
            .request_payload(empty_payload())
            .response_payload(empty_payload())
            .build();
    }

    #[test]
    #[should_panic]
    fn test_recorded_url_builder_panics_without_response_payload() {
        RecordedUrl::builder(String::from("https://example.com/"))
            .request_parts(&empty_request_parts())
            .request_payload(empty_payload())
            .response_parts(&empty_response_parts())
            .build();
    }
}
