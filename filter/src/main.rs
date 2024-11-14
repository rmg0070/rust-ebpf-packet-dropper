#![allow(warnings)]
// use anyhow::Context;
// use aya::{
//     include_bytes_aligned,
//     maps::{HashMap, MapData},
//     programs::{Xdp, XdpFlags},
//     Bpf,
// };
// use aya_log::BpfLogger;
// use log::{info, warn};
// use std::net::Ipv4Addr;
// use tokio::signal;

// #[tokio::main]
// async fn main() -> Result<(), anyhow::Error> {
//     // Initialize logging
//     env_logger::init();

//     // Load the eBPF program
//     #[cfg(debug_assertions)]
//     let mut bpf = Bpf::load(include_bytes_aligned!(
//         "../../target/bpfel-unknown-none/debug/xdp-drop"
//     ))?;
//     #[cfg(not(debug_assertions))]
//     let mut bpf = Bpf::load(include_bytes_aligned!(
//         "../../target/bpfel-unknown-none/release/xdp-drop"
//     ))?;
//     if let Err(e) = BpfLogger::init(&mut bpf) {
//         warn!("failed to initialize eBPF logger: {}", e);
//     }

//     let program: &mut Xdp = bpf.program_mut("xdp_firewall").unwrap().try_into()?;
//     program.load()?;
//     program.attach("enp0s3", XdpFlags::default())
//         .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

//     // } // `blocklist` mutable borrow ends here

//     // Blocking ports logic
//     // {
//     //     let mut port_blocklist: HashMap<_, u16, u16> = HashMap::try_from(bpf.map_mut("PORT_BLOCKLIST").unwrap())?;
//     //     let blocked_port: u16 = 80;
//     //     port_blocklist.insert(blocked_port, 0, 0)?;
//     //     info!("Blocking Port: 443 (HTTPS)");
//     // } // `port_blocklist` mutable borrow ends here

//     // // Blocking IPs logic
//     {
//         let mut blocklist: HashMap<_, u32, u32> = HashMap::try_from(bpf.map_mut("BLOCKLIST").unwrap())?;
//         let block_addr: u32 = Ipv4Addr::new(172, 20, 36, 60).try_into()?;
//         blocklist.insert(block_addr, 0, 0)?;
//         // info!("Blocking IP: 127.0.0.1");
//     } // `blocklist` mutable borrow ends here

    
//     // Wait for Ctrl-C to exit the program
//     info!("Waiting for Ctrl-C...");
//     signal::ctrl_c().await?;
//     info!("Exiting...");

//     Ok(())
// }
// use anyhow::{Context, Result};
// use aya::{
//     include_bytes_aligned,
//     maps::{HashMap, MapData},
//     programs::{Xdp, XdpFlags},
//     Bpf,
// };
// use aya_log::BpfLogger;
// use clap::Parser;
// use log::{info, warn};
// use std::net::Ipv4Addr;
// use tokio::signal;

// #[derive(Parser, Debug)]
// #[clap(author, version, about, long_about = None)]
// struct Args {
//     /// IP address to block, optional
//     #[clap(long)]
//     ip_address: Option<Ipv4Addr>,
//     /// Port number to block, optional
//     #[clap(long)]
//     port: Option<u16>,
// }

// #[tokio::main]
// async fn main() -> Result<()> {
//     // Initialize logging
//     env_logger::init();

//     // Parse command line arguments
//     let args = Args::parse();

//     // Load the eBPF program
//     #[cfg(debug_assertions)]
//     let mut bpf = Bpf::load(include_bytes_aligned!(
//         "../../target/bpfel-unknown-none/debug/xdp-drop"
//     ))?;
//     #[cfg(not(debug_assertions))]
//     let mut bpf = Bpf::load(include_bytes_aligned!(
//         "../../target/bpfel-unknown-none/release/xdp-drop"
//     ))?;
//     if let Err(e) = BpfLogger::init(&mut bpf) {
//         warn!("Failed to initialize eBPF logger: {}", e);
//         return Err(e).context("Failed to initialize eBPF logger");
//     }

//     let program: &mut Xdp = bpf.program_mut("xdp_firewall").unwrap().try_into()?;
//     program.load()?;
//     program.attach("enp0s3", XdpFlags::default())
//         .context("Failed to attach the XDP program with default flags")?;

//     // Handling optional IP blocking
//     if let Some(ip_address) = args.ip_address {
//         let mut blocklist: HashMap<_, u32, u32> = HashMap::try_from(bpf.map_mut("BLOCKLIST").unwrap())?;
//         let block_addr: u32 = u32::from(ip_address);  // Convert Ipv4Addr to u32 in network byte order
//         blocklist.insert(block_addr, 0, 0)?;
//         info!("Blocking IP: {}", ip_address);
//     } else {
//         info!("No IP address provided to block.");
//     }

//     // Handling optional Port blocking
//     if let Some(port) = args.port {
//         let mut port_blocklist: HashMap<_, u16, u16> = HashMap::try_from(bpf.map_mut("PORT_BLOCKLIST").unwrap())?;
//         port_blocklist.insert(port, 0, 0)?;
//         info!("Blocking Port: {}", port);
//     } else {
//         info!("No port number provided to block.");
//     }

//     // Wait for Ctrl-C to exit the program
//     info!("Waiting for Ctrl-C...");
//     signal::ctrl_c().await?;
//     info!("Exiting...");

//     Ok(())
// }

// RUST_LOG=info cargo xtask run --ip-address=192.168.112.1

use anyhow::{Context, Result, anyhow}; // General error handling
use aya::{  // Importing aya related functionalities
    Bpf, programs::{Xdp, XdpFlags}, include_bytes_aligned,
    maps::{HashMap, MapData},  // Data structures
};
use aya_log::BpfLogger;  // For logging within BPF programs
use clap::Parser;  // For parsing command-line arguments
use log::{info, warn};  // Logging utilities
use std::net::Ipv4Addr;  // Standard networking types
use tokio::signal;  // Async signal handling
use pnet::datalink;  // For network interface handling

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// IP address to block, optional
    #[clap(long)]
    ip_address: Option<Ipv4Addr>,
    /// Port number to block, optional
    #[clap(long)]
    port: Option<u16>,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();  // Initialize logging

    let args = Args::parse();  // Parse command line arguments

    let mut bpf = Bpf::load(include_bytes_aligned!(  // Load BPF program according to build configuration
        "../../target/bpfel-unknown-none/debug/xdp-drop"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        warn!("Failed to initialize eBPF logger: {}", e);
        return Err(e).context("Failed to initialize eBPF logger");
    }

    // Automatically select network interface
    let interfaces = datalink::interfaces();
    let default_interface = interfaces
        .into_iter()
        .find(|iface| iface.is_up() && !iface.is_loopback() && iface.ips.len() > 0)
        .ok_or_else(|| anyhow!("No suitable network interface found."))?;
    info!("Using interface: {}", default_interface.name);

    let program: &mut Xdp = bpf.program_mut("xdp_firewall").unwrap().try_into()?;
    program.load()?;
    program.attach(&default_interface.name, XdpFlags::default())
        .context(format!("Failed to attach the XDP program to {}", default_interface.name))?;

    // Handling optional IP and port blocking
    if let Some(ip_address) = args.ip_address {
        let mut blocklist: HashMap<_, u32, u32> = HashMap::try_from(bpf.map_mut("BLOCKLIST").unwrap())?;
        let block_addr: u32 = u32::from(ip_address);  // Convert Ipv4Addr to u32
        blocklist.insert(block_addr, 0, 0)?;
        info!("Blocking IP: {}", ip_address);
    } else {
        info!("No IP address provided to block.");
    }

    if let Some(port) = args.port {
        let mut port_blocklist: HashMap<_, u16, u16> = HashMap::try_from(bpf.map_mut("PORT_BLOCKLIST").unwrap())?;
        port_blocklist.insert(port, 0, 0)?;
        info!("Blocking Port: {}", port);
    } else {
        info!("No port number provided to block.");
    }

    // Wait for Ctrl-C to exit the program
    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
