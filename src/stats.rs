use std::collections::HashMap;

pub struct Stats {
    pub total: usize,
    pub proto_counts: HashMap<&'static str, usize>,
    pub ip_counts: HashMap<String, usize>,
    pub port_counts: HashMap<u16, usize>,
}

impl Stats {
    pub fn new() -> Self {
        Self {
            total: 0,
            proto_counts: HashMap::new(),
            ip_counts: HashMap::new(),
            port_counts: HashMap::new(),
        }
    }

    pub fn record(
        &mut self,
        proto: &'static str,
        src_ip: &str,
        dst_ip: &str,
        src_port: Option<u16>,
        dst_port: Option<u16>
    ) {
        self.total += 1;
        *self.proto_counts.entry(proto).or_insert(0) += 1;
        *self.ip_counts.entry(src_ip.to_string()).or_insert(0) += 1;
        *self.ip_counts.entry(dst_ip.to_string()).or_insert(0) += 1;
        if let Some(port) = src_port {
            *self.port_counts.entry(port).or_insert(0) += 1;
        }
        if let Some(port) = dst_port {
            *self.port_counts.entry(port).or_insert(0) += 1;
        }
    }

    pub fn print_summary(&self) {
        println!("\n--- Live Packet Stats ---");
        println!("Total packets captured: {}", self.total);

        // Protocols with bar chart
        self.print_proto_barchart();

        // Top talkers (IPs)
        let mut top_ips: Vec<_> = self.ip_counts.iter().collect();
        top_ips.sort_by(|a, b| b.1.cmp(a.1));
        println!("Top 5 IP addresses:");
        for (ip, count) in top_ips.into_iter().take(5) {
            println!("  {}: {}", ip, count);
        }

        // Top ports
        let mut top_ports: Vec<_> = self.port_counts.iter().collect();
        top_ports.sort_by(|a, b| b.1.cmp(a.1));
        println!("Top 5 Ports:");
        for (port, count) in top_ports.into_iter().take(5) {
            println!("  {:<5}: {}", port, count);
        }
        println!("-------------------------\n");
    }

    pub fn print_proto_barchart(&self) {
        println!("Protocol Usage:");
        // Find the maximum count for scaling
        let max = self.proto_counts.values().cloned().max().unwrap_or(1);
        for (proto, count) in &self.proto_counts {
            let bar_len = if max > 0 { ((count * 20) / max).max(1) } else { 1 };
            let bar = "▇".repeat(bar_len);
            println!("  {:<5} {:>5} {}", proto, count, bar);
        }
        println!();
    }

    pub fn print_port_barchart(&self) {
        println!("Port Usage Histogram:");
        let mut top_ports: Vec<_> = self.port_counts.iter().collect();
        top_ports.sort_by(|a, b| b.1.cmp(a.1));
        let max = top_ports
            .iter()
            .map(|(_, v)| **v)
            .max()
            .unwrap_or(1);
        for (port, count) in top_ports.iter().take(5) {
            let bar_len = if max > 0 { ((**count * 20) / max).max(1) } else { 1 };
            let bar = "▇".repeat(bar_len);
            println!("  {:<5} {:>5} {}", port, count, bar);
        }
        println!();
    }

    pub fn print_ip_barchart(&self) {
        println!("IP Address Histogram:");
        let mut top_ips: Vec<_> = self.ip_counts.iter().collect();
        top_ips.sort_by(|a, b| b.1.cmp(a.1));
        let max = top_ips
            .iter()
            .map(|(_, v)| **v)
            .max()
            .unwrap_or(1);
        for (ip, count) in top_ips.iter().take(5) {
            let bar_len = if max > 0 { ((**count * 20) / max).max(1) } else { 1 };
            let bar = "▇".repeat(bar_len);
            println!("  {:<15} {:>5} {}", ip, count, bar);
        }
        println!();
    }
}
