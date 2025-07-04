pub fn parse_and_print_http(payload: &[u8]) -> String {
    if let Ok(text) = std::str::from_utf8(payload) {
        if let Some(line) = text.lines().next() {
            if line.starts_with("GET") || line.starts_with("POST") || line.starts_with("HEAD") || line.starts_with("PUT") || line.starts_with("DELETE") {
                // Print for user
                println!("HTTP: {}", line.trim());
                // Return for CSV logging
                return line.trim().to_string();
            }
        }
    }
    String::new()
}
