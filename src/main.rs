mod packet;
mod parsers;
mod args;
mod filters;
mod stats;
mod output;
mod app_proto;

use packet::print_headers;
use parsers::proto_https::parse_and_print_http;
use parsers::proto_dns::parse_and_print_dns;
use parsers::proto_tls::parse_and_print_tls;
use args::Cli;
use output::logger::CsvLogger;
use output::json_logger::{JsonLogger, PacketRecord};
use filters::PacketFilter;
use stats::Stats;
use app_proto::{AppProto, list_supported};
use clap::Parser;
use pcap::{Device, Capture};
use etherparse::PacketHeaders;
use chrono::Local;
use std::io;

fn main() {
    // --- Application protocol parser selection ---
    println!("Which application protocols would you like to parse?");
    println!("Options: all, http, dns, tls, tcp, udp (comma-separated for multiple, e.g., http,dns,tcp), or none");

    let mut proto_input = String::new();
    io::stdin().read_line(&mut proto_input).expect("Failed to read input");
    let proto_input = proto_input.trim().to_lowercase();

    let selected_protos: Vec<AppProto> = if proto_input == "all" {
        list_supported()
    } else if proto_input == "none" {
        vec![]
    } else {
        proto_input
            .split(',')
            .filter_map(|s| AppProto::from_input(s.trim()))
            .collect()
    };

    if selected_protos.is_empty() {
        println!("No protocol parsers selected. Will only log headers and stats.");
    } else {
        println!(
            "Enabled protocol parsers: {}",
            selected_protos
                .iter()
                .map(|p| p.name())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    // --- Parse CLI arguments ---
    let cli = Cli::parse();

    // Build filter from CLI args
    let filter = PacketFilter {
        protocol: cli.protocol,
        port: cli.port,
        ip: cli.ip,
    };

    // Set up loggers
    let mut csv_logger = CsvLogger::new("packets.csv").expect("Could not open CSV log file.");
    let mut json_logger = JsonLogger::new("packets.json").expect("Could not open JSON log file.");

    // Set up stats
    let mut stats = Stats::new();

    // List all devices
    let devices = Device::list().expect("Failed to list devices.");
    println!("Available Devices:");
    for (i, device) in devices.iter().enumerate() {
        println!("{}: {}", i, device.name);
    }

    // Let user pick a device
    println!("Enter device number:");
    let mut index = String::new();
    io::stdin().read_line(&mut index).expect("Failed to read input");
    let index: usize = index.trim().parse().expect("Please enter a valid number.");
    let device = devices[index].clone();

    // Open device
    let mut cap = Capture::from_device(device)
        .unwrap()
        .promisc(true)
        .immediate_mode(true)
        .open()
        .unwrap();

    println!("Capturing... Press Ctrl+C to stop.");

    while let Ok(packet) = cap.next_packet() {
        let timestamp = Local::now();
        let ts_str = timestamp.format("%Y-%m-%d %H:%M:%S").to_string();
        print!("[{}] ", ts_str);

        if let Ok(headers) = PacketHeaders::from_ethernet_slice(packet.data) {
            // Gather info for filtering and logging
            let (proto, src_port, dst_port, src_ip, dst_ip) = match
                (&headers.ip, &headers.transport)
            {
                (
                    Some(etherparse::IpHeader::Version4(ipv4, _)),
                    Some(etherparse::TransportHeader::Tcp(tcp)),
                ) =>
                    (
                        "tcp",
                        Some(tcp.source_port),
                        Some(tcp.destination_port),
                        Some(format!("{}.{}.{}.{}", ipv4.source[0], ipv4.source[1], ipv4.source[2], ipv4.source[3])),
                        Some(format!("{}.{}.{}.{}", ipv4.destination[0], ipv4.destination[1], ipv4.destination[2], ipv4.destination[3])),
                    ),
                (
                    Some(etherparse::IpHeader::Version4(ipv4, _)),
                    Some(etherparse::TransportHeader::Udp(udp)),
                ) =>
                    (
                        "udp",
                        Some(udp.source_port),
                        Some(udp.destination_port),
                        Some(format!("{}.{}.{}.{}", ipv4.source[0], ipv4.source[1], ipv4.source[2], ipv4.source[3])),
                        Some(format!("{}.{}.{}.{}", ipv4.destination[0], ipv4.destination[1], ipv4.destination[2], ipv4.destination[3])),
                    ),
                _ => ("other", None, None, None, None),
            };

            // Apply filter
            if filter.matches(proto, src_port, dst_port, src_ip.as_deref(), dst_ip.as_deref()) {
                print_headers(&headers);

                // --- Application Protocol Parsing and Logging ---
                let link_len = headers.link.as_ref().map(|l| l.header_len()).unwrap_or(14);
                let ip_len = headers.ip.as_ref().map(|ip| ip.header_len()).unwrap_or(0);
                let trans_len = headers.transport.as_ref().map(|t| t.header_len()).unwrap_or(0);
                let data_offset = link_len + ip_len + trans_len;

                let mut http_info = String::new();
                let mut dns_info = String::new();
                let mut tls_info = String::new();
                let mut tcp_payload = String::new();
                let mut udp_payload = String::new();

                if packet.data.len() > data_offset {
                    let payload = &packet.data[data_offset..];

                    // HTTP
                    if
                        selected_protos.contains(&AppProto::Http) &&
                        proto == "tcp" &&
                        (src_port == Some(80) ||
                            dst_port == Some(80) ||
                            src_port == Some(8080) ||
                            dst_port == Some(8080))
                    {
                        http_info = parse_and_print_http(payload);
                    }

                    // DNS
                    if
                        selected_protos.contains(&AppProto::Dns) &&
                        proto == "udp" &&
                        (src_port == Some(53) || dst_port == Some(53))
                    {
                        dns_info = parse_and_print_dns(payload);
                    }

                    // TLS (SNI)
                    if
                        selected_protos.contains(&AppProto::Tls) &&
                        proto == "tcp" &&
                        (src_port == Some(443) || dst_port == Some(443))
                    {
                        tls_info = parse_and_print_tls(payload);
                    }

                    // TCP generic logging (when TCP is selected but not also HTTP/TLS on this packet)
                    if
                        selected_protos.contains(&AppProto::Tcp) &&
                        proto == "tcp" &&
                        !(
                            (selected_protos.contains(&AppProto::Http) && (src_port == Some(80) || dst_port == Some(80) || src_port == Some(8080) || dst_port == Some(8080)))
                            || (selected_protos.contains(&AppProto::Tls) && (src_port == Some(443) || dst_port == Some(443)))
                        )
                    {
                        tcp_payload = format!("{:02X?}", &payload[..payload.len().min(32)]);
                    }

                    // UDP generic logging (when UDP is selected but not also DNS)
                    if
                        selected_protos.contains(&AppProto::Udp) &&
                        proto == "udp" &&
                        !(selected_protos.contains(&AppProto::Dns) && (src_port == Some(53) || dst_port == Some(53)))
                    {
                        udp_payload = format!("{:02X?}", &payload[..payload.len().min(32)]);
                    }
                }

                // Log to CSV
                csv_logger
                    .log_packet(
                        &ts_str,
                        proto,
                        src_ip.as_deref().unwrap_or(""),
                        src_port,
                        dst_ip.as_deref().unwrap_or(""),
                        dst_port,
                        &http_info,
                        &dns_info,
                        &tls_info,
                        &tcp_payload,
                        &udp_payload,
                    )
                    .expect("Failed to write to CSV");

                // Log to JSON
                let record = PacketRecord {
                    timestamp: ts_str.clone(),
                    protocol: proto.to_string(),
                    src_ip: src_ip.clone().unwrap_or_default(),
                    src_port,
                    dst_ip: dst_ip.clone().unwrap_or_default(),
                    dst_port,
                    http_info: http_info.clone(),
                    dns_info: dns_info.clone(),
                    tls_info: tls_info.clone(),
                    tcp_payload: tcp_payload.clone(),
                    udp_payload: udp_payload.clone(),
                };
                json_logger.log_packet(&record).expect("Failed to write to JSON");

                // Record stats
                stats.record(
                    proto,
                    src_ip.as_deref().unwrap_or(""),
                    dst_ip.as_deref().unwrap_or(""),
                    src_port,
                    dst_port
                );

                // Show live stats every 20 packets
                if stats.total % 20 == 0 {
                    stats.print_summary();
                    stats.print_port_barchart();
                    stats.print_ip_barchart();
                }

                println!();
            }
        } else {
            println!("Could not parse headers for this packet");
        }
    }

    // Finish JSON file (close array)
    json_logger.finish().expect("Failed to close JSON array");
}
