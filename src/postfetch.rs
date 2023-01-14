use crate::recorded_url::RecordedUrl;

use futures::channel::mpsc::Receiver;
use futures::StreamExt;
use std::fs::OpenOptions;
use tracing::info;
use warcio::{WarcRecord, WarcWriter};

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

        while let Some(recorded_url) = rx.next().await {
            // info!("wrote to warc: {:?}", recorded_url.uri);
            // 2023-01-12 22:49:29,093 8610 INFO WarcWriterProcessor(tid=n/a) warcprox.writerthread.WarcWriterProcessor._log(writerthread.py:135)
            // 127.0.0.1 200 GET https://httpbin.org/get application/json size=485 sha1:12a3f9e7f0f8a92757dc4515fff52bf750a9855a response WARCPROX-20230113064929070-00000-nw73uzcl.warc.gz offset=348
            //         self.logger.info(
            //                 '%s %s %s %s %s size=%s %s %s %s offset=%s',
            //                 recorded_url.client_ip, recorded_url.status,
            //                 recorded_url.method, recorded_url.url.decode('utf-8'),
            //                 recorded_url.mimetype, recorded_url.size, payload_digest,
            //                 type_, filename, offset)
            let records = Vec::<WarcRecord>::from(recorded_url);
            //         self.logger.info(
            //                 '%s %s %s %s %s size=%s %s %s %s offset=%s',
            //                 recorded_url.client_ip, recorded_url.status,
            //                 recorded_url.method, recorded_url.url.decode('utf-8'),
            //                 recorded_url.mimetype, recorded_url.size, payload_digest,
            //                 type_, filename, offset)
            // info!("");
            for record in records {
                warc_writer.write_record(record)?;
            }
        }

        Ok::<(), std::io::Error>(())
    });
}
