pub struct PacketFilter {
    pub protocol: Option<String>,
    pub port: Option<u16>,
    pub ip: Option<String>,
}

impl PacketFilter {
    /// Checks if the current packet matches the filter
    pub fn matches(
        &self,
        protocol: &str,
        src_port: Option<u16>,
        dst_port: Option<u16>,
        src_ip: Option<&str>,
        dst_ip: Option<&str>,
    ) -> bool {
        if let Some(ref proto) = self.protocol {
            if proto != protocol {
                return false;
            }
        }
        if let Some(port) = self.port {
            if src_port != Some(port) && dst_port != Some(port) {
                return false;
            }
        }
        if let Some(ref filter_ip) = self.ip {
            let ip_match = src_ip == Some(filter_ip.as_str()) || dst_ip == Some(filter_ip.as_str());
            if !ip_match {
                return false;
            }
        }
        true
    }
}
