use chrono::{DateTime, Utc};
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
    pub(crate) uri: String,
    pub(crate) timestamp: DateTime<Utc>,
    pub(crate) request_line: Option<Vec<u8>>,
    pub(crate) request_headers: Option<Vec<u8>>,
    pub(crate) request_payload: Option<Payload>,
    pub(crate) response_status_line: Option<Vec<u8>>,
    pub(crate) response_headers: Option<Vec<u8>>,
    pub(crate) response_payload: Option<Payload>,
}

impl RecordedUrl {
    fn into_parts(
        mut self,
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
            self.request_line.take().unwrap(),
            self.request_headers.take().unwrap(),
            self.request_payload.take().unwrap(),
            self.response_status_line.take().unwrap(),
            self.response_headers.take().unwrap(),
            self.response_payload.take().unwrap(),
        )
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
