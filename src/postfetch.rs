use crate::recorded_url::RecordedUrl;

use futures::channel::mpsc::Receiver;
use futures::StreamExt;
use std::fs::OpenOptions;
use std::io::{Seek, SeekFrom};
use tracing::info;
use warcio::{WarcRecord, WarcWriter};

pub(crate) fn spawn_postfetch(mut rx: Receiver<RecordedUrl>, gzip: bool) {
    tokio::spawn(async move {
        let filename = if gzip {
            "warcprox-rs.warc.gz"
        } else {
            "warcprox-rs.warc"
        };
        let mut f = OpenOptions::new()
            .create(true) // .create_new(true)
            .append(true) // .write(true)
            .open(filename)?;
        f.seek(SeekFrom::End(0)).unwrap();
        let mut warc_writer = WarcWriter::new(f, gzip);

        while let Some(recorded_url) = rx.next().await {
            info!(
                "{} {} {} {} {} {} {} {} {}",
                recorded_url.status,
                recorded_url.method,
                recorded_url.uri,
                recorded_url
                    .mimetype
                    .as_ref()
                    .or(Some(&String::from("-")))
                    .unwrap(),
                recorded_url.response_payload.length,
                format!("sha256:{:x}", recorded_url.response_payload.sha256),
                "response",
                filename,
                warc_writer.tell()
            );
            let records = Vec::<WarcRecord>::from(recorded_url);
            for record in records {
                warc_writer.write_record(record)?;
            }
        }

        Ok::<(), std::io::Error>(())
    });
}
