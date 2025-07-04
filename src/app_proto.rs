#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppProto {
    Http,
    Dns,
    Tls,
    Tcp,
    Udp,
}

pub fn list_supported() -> Vec<AppProto> {
    vec![AppProto::Http, AppProto::Dns, AppProto::Tls, AppProto::Tcp, AppProto::Udp]
}

impl AppProto {
    pub fn from_input(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "http" => Some(AppProto::Http),
            "dns" => Some(AppProto::Dns),
            "tls" => Some(AppProto::Tls),
            "tcp" => Some(AppProto::Tcp),
            "udp" => Some(AppProto::Udp),
            _ => None,
        }
    }
    pub fn name(&self) -> &'static str {
        match self {
            AppProto::Http => "HTTP",
            AppProto::Dns => "DNS",
            AppProto::Tls => "TLS",
            AppProto::Tcp => "TCP",
            AppProto::Udp => "UDP",
        }
    }
}
