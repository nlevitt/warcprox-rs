use aho_corasick::AhoCorasick;
use chrono::Utc;
use gethostname::gethostname;
use rand::distributions::uniform::Uniform;
use rand::distributions::Distribution;
use rand::{thread_rng, Rng};
use std::fs::{create_dir, File};
use std::io::Read;
use std::path::PathBuf;
use warcio::{WarcRecord, WarcRecordInfo, WarcRecordWrite, WarcWriter};

pub(crate) struct RollingWarcWriter {
    dir: PathBuf,
    filename_template: String,
    gzip: bool,
    rollover_size: u64,
    current_warc_filename: Option<Vec<u8>>,
    inner: Option<WarcWriter<File>>,
    n: u64,
    random_token: String,
    port: u16,
}

const TEMPLATE_PARAM_KEYS: [&str; 7] = [
    "{timestamp14}",
    "{timestamp17}",
    "{serialno}",
    "{randomtoken}",
    "{maybe_dot_gz}",
    "{hostname}",
    // "{shorthostname}",
    "{port}",
];

struct LowercaseAlphanumeric;
const LOWERCASE_ALPHANUMERIC_BYTES: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";

impl<'a> RollingWarcWriter {
    pub(crate) fn new(
        dir: PathBuf,
        filename_template: String,
        gzip: bool,
        rollover_size: u64,
        port: u16,
    ) -> Self {
        let random_token: String = (0..8)
            .map(|_| thread_rng().sample(LowercaseAlphanumeric))
            .collect();
        Self {
            dir,
            filename_template,
            gzip,
            rollover_size,
            current_warc_filename: None,
            inner: None,
            n: 0,
            random_token,
            port,
        }
    }

    fn build_filename(&self) -> String {
        // todo: cache these in RollingWarcWriter?
        let template_param_finder: AhoCorasick = AhoCorasick::new(TEMPLATE_PARAM_KEYS);

        impl Distribution<char> for LowercaseAlphanumeric {
            fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> char {
                let byte_picker: Uniform<usize> =
                    Uniform::from(0..LOWERCASE_ALPHANUMERIC_BYTES.len());
                LOWERCASE_ALPHANUMERIC_BYTES[byte_picker.sample(rng)] as char
            }
        }

        let mut new_filename_buf = String::new();
        template_param_finder.replace_all_with(
            &self.filename_template,
            &mut new_filename_buf,
            |_, match_, output_buf| {
                if match_ == "{timestamp17}" {
                    // let t17 = Utc::now().format("%Y%m%d%H%M%S%.3f").to_string(); // extra dot
                    let now = Utc::now();
                    let mut t17 = now.format("%Y%m%d%H%M%S").to_string();
                    t17.push_str(&format!("{:03}", now.timestamp_subsec_millis()));
                    output_buf.push_str(&t17);
                } else if match_ == "{timestamp14}" {
                    let now = Utc::now();
                    let t14 = now.format("%Y%m%d%H%M%S").to_string();
                    output_buf.push_str(&t14);
                } else if match_ == "{hostname}" {
                    output_buf.push_str(
                        &gethostname()
                            .into_string()
                            .unwrap_or(String::from("unknown")),
                    );
                } else if match_ == "{port}" {
                    output_buf.push_str(&self.port.to_string());
                } else if match_ == "{serialno}" {
                    output_buf.push_str(&format!("{:05}", self.n));
                } else if match_ == "{randomtoken}" {
                    output_buf.push_str(&self.random_token);
                } else if match_ == "{maybe_dot_gz}" {
                    if self.gzip {
                        output_buf.push_str(".gz");
                    }
                }
                true
            },
        );
        new_filename_buf
    }

    /// Returns Ok((warc_path, offset))
    pub(crate) fn write_records<R: Read>(
        &mut self,
        records: Vec<WarcRecord<R>>,
    ) -> Result<WarcRecordInfo, std::io::Error> {
        if self.inner.is_some() && self.inner.as_mut().unwrap().tell() > self.rollover_size {
            // It's time to roll over
            self.inner = None;
        }

        if self.inner.is_none() {
            // Either we just started or we just rolled over, so open new warc
            if !self.dir.exists() {
                create_dir(&self.dir)?;
            }

            let warc_filename = self.build_filename();

            let mut p = self.dir.to_path_buf();
            p.push(&warc_filename);
            let f = File::create(&p)?;
            let w = WarcWriter::new(f, self.gzip);

            self.inner = Some(w);
            self.current_warc_filename = Some(Vec::from(warc_filename.as_bytes()));
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

// todo:
//
// #[cfg(test)]
// mod tests {
//     fn test_does_not_create_dir_or_files_until_record_written() {}
//     fn test_writes_warcinfo_record() {}
//     fn test_writes_records() {}
//     fn test_rolls_over_at_rollover_size() {}
//     fn test_does_not_split_related_records() {}
// }
