use std::fs::OpenOptions;
use std::io::{ Write, BufWriter };

pub struct CsvLogger {
    writer: BufWriter<std::fs::File>,
}

impl CsvLogger {
    /// Initialize logger (append or create new CSV file)
    pub fn new(filename: &str) -> std::io::Result<Self> {
        let file = OpenOptions::new().append(true).create(true).open(filename)?;
        let mut writer = BufWriter::new(file);

        // Write CSV header if file is new
        if std::fs::metadata(filename)?.len() == 0 {
            writeln!(
                writer,
                "timestamp,protocol,src_ip,src_port,dst_ip,dst_port,http_info,dns_info,tls_info,tcp_payload,udp_payload"
            )?;
        }

        Ok(Self { writer })
    }

    /// Log one packet as a row. http_info and dns_info can be empty strings.
    pub fn log_packet(
        &mut self,
        timestamp: &str,
        protocol: &str,
        src_ip: &str,
        src_port: Option<u16>,
        dst_ip: &str,
        dst_port: Option<u16>,
        http_info: &str,
        dns_info: &str,
        tls_info: &str,
        tcp_payload: &str,
        udp_payload: &str,
    ) -> std::io::Result<()> {
        writeln!(
            self.writer,
            "{},{},{},{},{},{},{},{},{},{},{}",
            timestamp,
            protocol,
            src_ip,
            src_port.map_or(String::from(""), |p| p.to_string()),
            dst_ip,
            dst_port.map_or(String::from(""), |p| p.to_string()),
            http_info.replace(",", ";"),
            dns_info.replace(",", ";"),
            tls_info.replace(",", ";"),
            tcp_payload.replace(",", ";"),
            udp_payload.replace(",", ";")
        )?;
        self.writer.flush()
    }
}
