pub fn parse_and_print_dns(payload: &[u8]) -> String {
    if let Ok(packet) = dns_parser::Packet::parse(payload) {
        let mut queries = Vec::new();
        for q in packet.questions {
            let info = format!("{}", q.qname);
            println!("DNS Query: {}", info);
            queries.push(info);
        }
        return queries.join(";");
    }
    String::new()
}
