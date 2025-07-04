# netsniffer-rs

A network packet sniffing and analysis tool written in Rust. It captures packets from a selected network interface, allows parsing of various application-level protocols, filters traffic, logs data to CSV and JSON files, and displays live statistics.

## Features

*   Packet capture from a chosen network interface.
*   Interactive selection of application protocols to parse (HTTP, DNS, TLS, and generic TCP/UDP payloads).
*   Filtering by protocol (TCP/UDP), port, and IP address via command-line arguments.
*   Logging of detailed packet information to `packets.csv` and `packets.json`.
*   Real-time display of traffic statistics, including:
    *   Total packets captured.
    *   Breakdown by protocol.
    *   Top source/destination ports.
    *   Top source/destination IP addresses.

## Requirements

*   **Rust:** Ensure you have Rust and Cargo installed. You can get them from [rustup.rs](https://rustup.rs/).
*   **Packet Capture Library:**
    *   **Windows:** Requires Npcap. Npcap is installed with Nmap. Download Nmap (which includes Npcap) from [nmap.org](https://nmap.org/download.html). Ensure the Npcap driver is installed in a way that its libraries are accessible by the `pcap` crate. This might mean having the Npcap SDK directory in your system's PATH or ensuring necessary DLLs (like `Packet.dll`) are available. The user specifically mentioned: "you need the nmap 64x bit Lib put in the same folder as this for this to run" - this typically refers to ensuring `Packet.dll` and potentially other Npcap libraries are findable by the executable, either by being in the same folder or in the system PATH.
    *   **Linux:** Requires `libpcap-dev` (or equivalent, e.g., `libcap-devel` on Fedora).
        ```bash
        sudo apt-get install libpcap-dev
        ```
    *   **macOS:** Comes with `libpcap` by default.

## Building

To build the project, navigate to the project directory and run:

```bash
cargo build --release
```
The executable will be located at `target/release/netsniffer-rs`.

## Running

1.  Execute the compiled program:
    *   Using cargo: `cargo run`
    *   Directly: `target/release/netsniffer-rs` (or `.\target\release\netsniffer-rs.exe` on Windows)

2.  **Select Application Protocols:**
    The tool will first ask which application protocols you'd like to parse.
    You can enter:
    *   `all` (to parse HTTP, DNS, TLS, TCP, UDP)
    *   A comma-separated list, e.g., `http,dns,tcp`
    *   `none` (to only log basic packet headers and stats without deep parsing)

3.  **Select Network Device:**
    It will then list available network devices. Enter the number corresponding to the device you want to sniff packets from.

4.  **Capture:**
    The tool will start capturing and displaying live statistics. Press `Ctrl+C` in the terminal to stop capturing.

## Command-line Arguments (for filtering)

You can filter captured packets using the following command-line arguments:

*   `--protocol <tcp|udp|all>`: Filter packets by the specified transport protocol. If not specified, defaults to `all`.
    *   Example: `target/release/netsniffer-rs --protocol tcp`
*   `--port <port_number>`: Filter packets that have the specified port as either source or destination.
    *   Example: `target/release/netsniffer-rs --port 443`
*   `--ip <ip_address>`: Filter packets that have the specified IP address as either source or destination.
    *   Example: `target/release/netsniffer-rs --ip 192.168.1.100`

All filter arguments can be combined:
```bash
target/release/netsniffer-rs --protocol tcp --port 443 --ip 1.1.1.1
```

## Output

*   **Console:** Live statistics are printed to the console every 20 packets.
*   **`packets.csv`:** A CSV file containing detailed information for each captured (and filtered) packet.
*   **`packets.json`:** A JSON file containing detailed information for each captured (and filtered) packet.

## Project Structure / Modules

*   `src/main.rs`: Contains the main application logic, including the packet capture loop and user interaction.
*   `src/args.rs`: Defines and parses command-line arguments using `clap`.
*   `src/packet.rs`: Handles the printing of packet header information.
*   `src/parsers/`: Directory containing modules for parsing specific application-layer protocols:
    *   `proto_dns.rs`: DNS protocol parser.
    *   `proto_https.rs`: HTTP protocol parser.
    *   `proto_tls.rs`: TLS (SNI) parser.
*   `src/filters.rs`: Implements the logic for filtering packets based on command-line arguments.
*   `src/stats.rs`: Handles the calculation, storage, and display of traffic statistics.
*   `src/output/`: Directory containing modules for outputting captured data:
    *   `logger.rs`: Defines a trait for logging and implements the CSV logger.
    *   `json_logger.rs`: Implements the JSON logger.
*   `src/app_proto.rs`: Defines the `AppProto` enum used for selecting which application protocols to parse.

## Troubleshooting

*   **"pcap library not found," "failed to link," or similar errors during build or runtime:**
    *   Ensure you have installed Npcap (Windows) or `libpcap-dev` (Linux) as described in the [Requirements](#requirements) section.
    *   On Windows, make sure the Npcap SDK's `Lib` or `Lib/x64` folder is added to your `LIBRARY_PATH` environment variable, or that required DLLs (like `Packet.dll`) are in your system's PATH or in the same directory as the `netsniffer-rs` executable. For development with `cargo`, placing `Packet.dll` from Npcap into the root of the Rust project or `C:\Windows\System32\` (and `SysWOW64` for 32-bit version if needed) can sometimes help the `pcap` crate find it during compilation and runtime.
*   **Permission denied errors when capturing:**
    *   On Linux and macOS, you might need to run the executable with `sudo` or adjust system permissions to allow packet capture by non-root users.
    *   On Windows, ensure Npcap was installed with administrator privileges and that your user account has permission to access capture devices.
```
