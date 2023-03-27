use crate::recorded_url::RecordedUrl;
use crate::rolling_warc_writer::RollingWarcWriter;
use futures::channel::mpsc;
use futures::StreamExt as _;
use std::borrow::Cow;
use std::path::PathBuf;
use tempfile::SpooledTempFile;
use tracing::info;
use warcio::{WarcRecord, WarcRecordInfo};

fn log(warc_record_info: WarcRecordInfo) {
    let status_str = match &warc_record_info.http_metadata.status {
        Some(status) => status.as_str(),
        None => "-",
    };
    let method_str = match &warc_record_info.http_metadata.method {
        Some(method) => method.as_str(),
        None => "-",
    };
    let uri_str = match &warc_record_info.warc_record_metadata.warc_target_uri {
        Some(uri) => String::from_utf8_lossy(uri),
        None => Cow::Borrowed("-"),
    };
    let content_length_str = match &warc_record_info.http_metadata.content_length {
        Some(content_length) => content_length.to_string(),
        None => String::from("-"),
    };
    let digest_str = match &warc_record_info.warc_record_metadata.warc_payload_digest {
        Some(digest) => String::from_utf8_lossy(&digest),
        None => Cow::Borrowed("-"),
    };
    let warc_filename_str = match &warc_record_info.warc_record_location.warc_filename {
        Some(warc_filename) => String::from_utf8_lossy(warc_filename),
        None => Cow::Borrowed("-"),
    };
    info!(
        "{} {} {} {} {} {} {} {}",
        status_str,
        method_str,
        uri_str,
        &warc_record_info
            .http_metadata
            .mimetype
            .unwrap_or(String::from("-")),
        content_length_str,
        digest_str,
        warc_filename_str,
        warc_record_info.warc_record_location.offset
    );
}

pub(crate) struct Postfetch {
    warc_writer: RollingWarcWriter,
    recorded_url_rx: mpsc::Receiver<RecordedUrl>,
}

impl Postfetch {
    pub fn new(
        recorded_url_rx: mpsc::Receiver<RecordedUrl>,
        warc_filename_template: String,
        gzip: bool,
        port: u16,
    ) -> Self {
        Postfetch {
            recorded_url_rx,
            warc_writer: RollingWarcWriter::new(
                PathBuf::from("./warcs"), // todo: make this a command line option
                warc_filename_template,
                gzip,
                1_000_000_000, // todo: make this a command line option
                port,
            ),
        }
    }

    // pub async fn start<F: Future<Output = ()> + Send + 'static>(
    // shutdown_signal: F,
    pub async fn start(mut self) -> Result<(), std::io::Error> {
        while let Some(recorded_url) = self.recorded_url_rx.next().await {
            let records = Vec::<WarcRecord<SpooledTempFile>>::from(recorded_url);
            let warc_record_info = self.warc_writer.write_records(records)?;
            log(warc_record_info);
        }
        Ok(())
    }
}

// todo:
//
// #[cfg(test)]
// mod tests {
//     fn test_build_filename() {}
//     fn test_rolling_warc_writer() {}
//     fn test_crawl_log() {}
//     fn test_postfetch_loop() {}
// }
