pub fn parse_and_print_tls(payload: &[u8]) -> String {
    if payload.len() < 5 || payload[0] != 0x16 { // 0x16 = Handshake
        return String::new();
    }
    // TLS Record: [ContentType=0x16][Version][Length]
    let mut i = 5;
    while i + 4 < payload.len() {
        // Find Server Name extension (type 0x00 0x00)
        if i + 4 < payload.len() && payload[i] == 0x00 && payload[i + 1] == 0x00 {
            // naive, not robust; a real parser would use rustls or tls-parser crate
            // Extract length and SNI string (skip ext header: 2 type, 2 len, 1 name_type, 2 name_len)
            if i + 9 < payload.len() {
                let name_len = ((payload[i + 7] as usize) << 8) | (payload[i + 8] as usize);
                if i + 9 + name_len <= payload.len() {
                    let sni = &payload[i + 9 .. i + 9 + name_len];
                    if let Ok(host) = std::str::from_utf8(sni) {
                        println!("  [TLS] SNI: {}", host);
                        return host.to_string();
                    }
                }
            }
        }
        i += 1;
    }
    String::new()
}
