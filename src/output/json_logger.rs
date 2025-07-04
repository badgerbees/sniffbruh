use std::fs::OpenOptions;
use std::io::{Write, BufWriter};
use serde::Serialize;
use std::io::Seek;

#[derive(Serialize)]
pub struct PacketRecord {
    pub timestamp: String,
    pub protocol: String,
    pub src_ip: String,
    pub src_port: Option<u16>,
    pub dst_ip: String,
    pub dst_port: Option<u16>,
    pub http_info: String,
    pub dns_info: String,
    pub tls_info: String,
    pub tcp_payload: String,
    pub udp_payload: String
}

pub struct JsonLogger {
    writer: BufWriter<std::fs::File>,
    first: bool,
}

impl JsonLogger {
    pub fn new(filename: &str) -> std::io::Result<Self> {
        let file = OpenOptions::new()
            .append(true)
            .create(true)
            .open(filename)?;
        let mut writer = BufWriter::new(file);

        // Start array if file is empty
        let meta = std::fs::metadata(filename)?;
        if meta.len() == 0 {
            writer.write_all(b"[\n")?;
        } else {
            // If appending, remove the last "]" so we can keep writing
            // (assumes the file ends with "]\n")
            let mut f = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(filename)?;
            f.seek(std::io::SeekFrom::End(-2)).ok();
            f.write_all(b",\n").ok();
        }

        Ok(Self { writer, first: true })
    }

    pub fn log_packet(&mut self, record: &PacketRecord) -> std::io::Result<()> {
        if !self.first {
            self.writer.write_all(b",\n")?;
        }
        let s = serde_json::to_string_pretty(&record)?;
        self.writer.write_all(s.as_bytes())?;
        self.first = false;
        self.writer.flush()
    }

    pub fn finish(mut self) -> std::io::Result<()> {
        self.writer.write_all(b"\n]\n")?;
        self.writer.flush()
    }
}
