use etherparse::PacketHeaders;

/// Formats a MAC address as string.
pub fn format_mac(addr: &[u8; 6]) -> String {
    addr.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(":")
}

/// Formats an IPv4 address as string.
pub fn format_ipv4(addr: &[u8; 4]) -> String {
    format!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3])
}

/// Formats an IPv6 address as string.
pub fn format_ipv6(addr: &[u8; 16]) -> String {
    addr.chunks(2)
        .map(|chunk| format!("{:02x}{:02x}", chunk[0], chunk[1]))
        .collect::<Vec<_>>()
        .join(":")
}

/// Pretty-prints all supported headers (Ethernet, IP, TCP/UDP).
pub fn print_headers(headers: &PacketHeaders) {
    // Ethernet
    if let Some(ref eth) = headers.link {
        print!(
            "Ethernet: {} -> {} ",
            format_mac(&eth.source),
            format_mac(&eth.destination)
        );
    }
    // IP
    if let Some(ref ip) = headers.ip {
        match ip {
            etherparse::IpHeader::Version4(ipv4, _) => {
                print!(
                    "IPv4: {} -> {} ",
                    format_ipv4(&ipv4.source),
                    format_ipv4(&ipv4.destination)
                );
            }
            etherparse::IpHeader::Version6(ipv6, _) => {
                print!(
                    "IPv6: {} -> {} ",
                    format_ipv6(&ipv6.source),
                    format_ipv6(&ipv6.destination)
                );
            }
        }
    }
    // Transport (TCP/UDP)
    if let Some(ref transport) = headers.transport {
        match transport {
            etherparse::TransportHeader::Tcp(tcp) => {
                print!("| TCP: {} -> {}", tcp.source_port, tcp.destination_port);
            }
            etherparse::TransportHeader::Udp(udp) => {
                print!("| UDP: {} -> {}", udp.source_port, udp.destination_port);
            }
            _ => print!("| Other transport protocol"),
        }
    }
}
