use chrono::{DateTime, Utc};
use hudsucker::hyper::http::{request, response};
use hudsucker::hyper::HeaderMap;
use sha2::digest::Output;
use sha2::Sha256;
use std::io::{Cursor, Read};
use tempfile::SpooledTempFile;
use warcio::{WarcRecord, WarcRecordBuilder, WarcRecordType};

#[derive(Debug)]
pub(crate) struct Payload {
    pub(crate) sha256: Output<Sha256>,
    pub(crate) payload: SpooledTempFile,
    pub(crate) length: u64,
}

#[derive(Debug)]
pub(crate) struct RecordedUrl {
    uri: String,
    timestamp: DateTime<Utc>,
    request_line: Vec<u8>,
    request_headers: Vec<u8>,
    request_payload: Payload,
    response_status_line: Vec<u8>,
    response_headers: Vec<u8>,
    response_payload: Payload,
}

impl RecordedUrl {
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
            parts.status.canonical_reason().unwrap()
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
    request_line: Option<Vec<u8>>,
    request_headers: Option<Vec<u8>>,
    request_payload: Option<Payload>,
    response_status_line: Option<Vec<u8>>,
    response_headers: Option<Vec<u8>>,
    response_payload: Option<Payload>,
}

impl RecordedUrlBuilder {
    pub(crate) fn new(uri: String) -> Self {
        Self {
            uri,
            timestamp: Utc::now(),
            request_line: None,
            request_headers: None,
            request_payload: None,
            response_status_line: None,
            response_headers: None,
            response_payload: None,
        }
    }

    pub(crate) fn request_parts(mut self, parts: &request::Parts) -> Self {
        self.request_line = Some(request_line_as_bytes(parts));
        self.request_headers = Some(headers_as_bytes(&parts.headers));
        self
    }

    pub(crate) fn request_payload(mut self, payload: Payload) -> Self {
        self.request_payload = Some(payload);
        self
    }

    pub(crate) fn response_parts(mut self, parts: &response::Parts) -> Self {
        self.response_status_line = Some(response_status_line_as_bytes(parts));
        self.response_headers = Some(headers_as_bytes(&parts.headers));
        self
    }

    pub(crate) fn response_payload(mut self, payload: Payload) -> Self {
        self.response_payload = Some(payload);
        self
    }

    pub(crate) fn build(mut self) -> RecordedUrl {
        RecordedUrl {
            uri: self.uri,
            timestamp: self.timestamp,
            request_line: self.request_line.take().unwrap(),
            request_headers: self.request_headers.take().unwrap(),
            request_payload: self.request_payload.take().unwrap(),
            response_status_line: self.response_status_line.take().unwrap(),
            response_headers: self.response_headers.take().unwrap(),
            response_payload: self.response_payload.take().unwrap(),
        }
    }
}

// fn response_record(mut recorded_url: &RecordedUrl) -> WarcRecord {
fn response_record(
    uri: &String,
    timestamp: DateTime<Utc>,
    response_status_line: Vec<u8>,
    response_headers: Vec<u8>,
    response_payload: Payload,
) -> WarcRecord {
    let full_http_response_length: u64 = response_status_line.len() as u64
        + response_headers.len() as u64
        + 2
        + response_payload.length;
    let full_http_response = Cursor::new(response_status_line)
        .chain(Cursor::new(response_headers))
        .chain(&b"\r\n"[..])
        .chain(response_payload.payload);

    let record = WarcRecordBuilder::new()
        .warc_type(WarcRecordType::Response)
        .warc_date(timestamp)
        .warc_target_uri(uri.as_bytes())
        // .warc_ip_address
        .warc_payload_digest(format!("sha256:{:x}", &response_payload.sha256).as_bytes())
        .content_type(b"application/http;msgtype=response")
        .content_length(full_http_response_length)
        .body(Box::new(full_http_response))
        .build();
    record
}

// fn request_record(mut recorded_url: &RecordedUrl) -> WarcRecord {
fn request_record(
    uri: &String,
    timestamp: DateTime<Utc>,
    request_line: Vec<u8>,
    request_headers: Vec<u8>,
    request_payload: Payload,
) -> WarcRecord {
    let full_http_request_length: u64 =
        request_line.len() as u64 + request_headers.len() as u64 + 2 + request_payload.length;
    let full_http_request = Cursor::new(request_line)
        .chain(Cursor::new(request_headers))
        .chain(&b"\r\n"[..])
        .chain(request_payload.payload);

    let record = WarcRecordBuilder::new()
        .warc_type(WarcRecordType::Request)
        .warc_date(timestamp)
        .warc_target_uri(uri.as_bytes())
        // .warc_ip_address
        .warc_payload_digest(format!("sha256:{:x}", &request_payload.sha256).as_bytes())
        .content_type(b"application/http;msgtype=request")
        .content_length(full_http_request_length)
        .body(Box::new(full_http_request))
        .build();
    record
}

impl From<RecordedUrl> for Vec<WarcRecord> {
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

        let mut records = Vec::new();
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
