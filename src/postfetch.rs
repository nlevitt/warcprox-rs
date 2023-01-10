use crate::proxy::RecordedUrl;

use chrono::Utc;
use futures::channel::mpsc::Receiver;
use futures::StreamExt;
use std::fs::OpenOptions;
use std::io::{Cursor, Read};
use tracing::info;
use warcio::{WarcRecordBuilder, WarcRecordType, WarcWriter};

pub(crate) fn spawn_postfetch(mut rx: Receiver<RecordedUrl>, gzip: bool) {
    tokio::spawn(async move {
        // WARC/1.0
        // WARC-Type: response
        // WARC-Record-ID: <urn:uuid:6a050210-b1f2-42c9-944a-b1e7c63efec7>
        // WARC-Date: 2023-01-05T08:07:26Z
        // WARC-Target-URI: https://httpbin.org/get
        // WARC-IP-Address: 54.163.169.210
        // Content-Type: application/http;msgtype=response
        // WARC-Payload-Digest: sha1:66777e0225f14e2667e794d3cd1714ba0a639cf7
        // Content-Length: 485
        // WARC-Block-Digest: sha1:666cb28dbda701b12ddbcf779c735aa2e672ac23
        //
        let f = OpenOptions::new()
            .create(true) // .create_new(true)
            .append(true) // .write(true)
            .open(if gzip {
                "warcprox-rs.warc.gz"
            } else {
                "warcprox-rs.warc"
            })?;
        let mut warc_writer = WarcWriter::new(f, gzip);

        while let Some(mut recorded_url) = rx.next().await {
            let full_http_response_length: u64 =
                recorded_url.response_status_line.as_ref().unwrap().len() as u64
                    + recorded_url.response_headers.as_ref().unwrap().len() as u64
                    + 2
                    + recorded_url.payload_length;
            let full_http_response = Cursor::new(recorded_url.response_status_line.take().unwrap())
                .chain(Cursor::new(recorded_url.response_headers.take().unwrap()))
                .chain(&b"\r\n"[..])
                .chain(recorded_url.response_payload_recorder.unwrap());

            let record = WarcRecordBuilder::new()
                .warc_type(WarcRecordType::Response)
                .warc_date(Utc::now())
                .warc_target_uri(recorded_url.uri.as_bytes())
                // .warc_ip_address
                .content_type(b"application/http;msgtype=response")
                .content_length(full_http_response_length)
                .body(Box::new(full_http_response))
                .build();
            warc_writer.write_record(record)?;
            info!("wrote to warc: {:?}", recorded_url.uri);
        }

        Ok::<(), std::io::Error>(())
    });
}
