use crate::recorded_url::RecordedUrl;

use futures::channel::mpsc::Receiver;
use futures::StreamExt;
use std::fs::{create_dir, File, OpenOptions};
use std::io::{Error, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use tempfile::SpooledTempFile;
use tracing::info;
use warcio::{WarcRecord, WarcRecordWrite, WarcWriter};

struct RollingWarcWriter<'a> {
    dir: &'a Path,
    gzip: bool,
    rollover_size: u64,

    current_warc_path: Option<PathBuf>,
    inner: Option<WarcWriter<File>>,
    n: u64,
}

impl<'a> RollingWarcWriter<'a> {
    /// Returns Ok((warc_path, offset))
    fn write_records<R: Read>(
        &mut self,
        records: Vec<WarcRecord<R>>,
    ) -> Result<(&Path, u64), Error> {
        if self.inner.is_some() && self.inner.as_mut().unwrap().tell() > self.rollover_size {
            // it's time to roll over
            self.inner = None;
        }

        if self.inner.is_none() {
            // open new warc because either we just started or we just rolled over
            if !self.dir.exists() {
                create_dir(self.dir)?;
            }
            let mut p = self.dir.to_path_buf();
            p.push(format!("warcprox-rs-{:05}.warc.gz", self.n));
            let f = File::create(&p)?;
            self.current_warc_path = Some(p);
            let w = WarcWriter::new(f, self.gzip);
            self.inner = Some(w);
            self.n += 1;
        }

        let warc_writer = self.inner.as_mut().unwrap();
        let current_warc_path = self.current_warc_path.as_ref().unwrap();
        let offset = warc_writer.tell();
        for mut record in records {
            warc_writer.write_record(&mut record)?;
        }

        Ok((current_warc_path, offset))
    }
}

pub(crate) fn spawn_postfetch(mut rx: Receiver<RecordedUrl>, gzip: bool) {
    tokio::spawn(async move {
        let mut warc_writer = RollingWarcWriter {
            dir: "./warcs".as_ref(),
            gzip,
            rollover_size: 1000000,
            current_warc_path: None,
            inner: None,
            n: 0,
        };
        /*
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
         */

        while let Some(recorded_url) = rx.next().await {
            // let digest = format!("sha256:{:x}", &recorded_url.response_payload.sha256);

            let records = Vec::<WarcRecord<SpooledTempFile>>::from(recorded_url);
            // let records = Vec::<WarcRecord<Box<dyn Read>>>::from(recorded_url);
            let (warc, offset) = warc_writer.write_records(records)?;

            info!("{:?} {}", warc, offset);
            /*
            info!(
                "{} {} {} {} {} {} {} {:?} {}",
                recorded_url.status,
                recorded_url.method,
                recorded_url.uri,
                recorded_url
                    .mimetype
                    .as_ref()
                    .or(Some(&String::from("-")))
                    .unwrap(),
                recorded_url.response_payload.length,
                "fdjsiap",
                "response",
                warc,
                offset
            );
             */
        }

        Ok::<(), Error>(())
    });
}
