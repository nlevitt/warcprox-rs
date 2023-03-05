use crate::recorded_url::RecordedUrl;
use std::borrow::Cow;

use futures::channel::mpsc::Receiver;
use futures::StreamExt;
use std::fs::{create_dir, File};
use std::io::{Error, Read};
use std::path::Path;
use tempfile::SpooledTempFile;
use tracing::info;
use warcio::{WarcRecord, WarcRecordInfo, WarcRecordWrite, WarcWriter};

struct RollingWarcWriter<'a> {
    dir: &'a Path,
    gzip: bool,
    rollover_size: u64,
    current_warc_filename: Option<Vec<u8>>,
    inner: Option<WarcWriter<File>>,
    n: u64,
}

impl<'a> RollingWarcWriter<'a> {
    /// Returns Ok((warc_path, offset))
    fn write_records<R: Read>(
        &mut self,
        records: Vec<WarcRecord<R>>,
    ) -> Result<WarcRecordInfo, Error> {
        if self.inner.is_some() && self.inner.as_mut().unwrap().tell() > self.rollover_size {
            // It's time to roll over
            self.inner = None;
        }

        if self.inner.is_none() {
            // Either we just started or we just rolled over, so open new warc
            if !self.dir.exists() {
                create_dir(self.dir)?;
            }

            let warc_filename = format!("warcprox-rs-{:05}.warc.gz", self.n);

            let mut p = self.dir.to_path_buf();
            p.push(&warc_filename);
            let f = File::create(&p)?;
            let w = WarcWriter::new(f, self.gzip);

            self.inner = Some(w);
            self.current_warc_filename = Some(Vec::from(warc_filename));
            self.n += 1;
        }

        // Only now do we know the `WARC-Filename` 🫠 What do we do?
        // - Keep the WarcRecordBuilder around until now?
        // - Pass filename as argument to `write_record`? (Going with this for now)
        // - Make WarcWriter aware of it?
        // - Set it on the WarcRecord directly here?

        let warc_writer = self.inner.as_mut().unwrap();
        let mut first_record_info = None;
        for record in records {
            let warc_record_info =
                warc_writer.write_record(record, (&self.current_warc_filename).as_ref())?;

            if first_record_info.is_none() {
                first_record_info = Some(warc_record_info);
            }
        }

        Ok(first_record_info.unwrap())
    }
}

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

pub(crate) fn spawn_postfetch(mut rx: Receiver<RecordedUrl>, gzip: bool) {
    tokio::spawn(async move {
        let mut warc_writer = RollingWarcWriter {
            dir: "./warcs".as_ref(),
            gzip,
            rollover_size: 1000000,
            current_warc_filename: None,
            inner: None,
            n: 0,
        };

        while let Some(recorded_url) = rx.next().await {
            let records = Vec::<WarcRecord<SpooledTempFile>>::from(recorded_url);
            let warc_record_info = warc_writer.write_records(records)?;
            log(warc_record_info);
        }

        Ok::<(), Error>(())
    });
}
