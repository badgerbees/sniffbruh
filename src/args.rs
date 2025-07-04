use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about)]
pub struct Cli {
    /// Filter by protocol: tcp, udp, or all (default)
    #[arg(long)]
    pub protocol: Option<String>,

    /// Filter by port number
    #[arg(long)]
    pub port: Option<u16>,

    /// Filter by IP address (source or destination)
    #[arg(long)]
    pub ip: Option<String>,
}
