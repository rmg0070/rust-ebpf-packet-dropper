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
use notify::{Watcher, RecursiveMode, watcher}; // File-watching
use std::sync::{Arc, Mutex};
use std::{fs, collections::HashSet};
use std::time::Duration;
use std::path::Path;

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

// Shared state for IP and Port blocklists
struct SharedState {
    ip_blocklist: HashMap<MapData, u32, u32>,
    port_blocklist: HashMap<MapData, u16, u16>,
    known_ips: HashSet<u32>, // To track currently blocked IPs
    known_ports: HashSet<u16>, // To track currently blocked Ports
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

    // Initialize blocklists
    let ip_blocklist = HashMap::try_from(bpf.map_mut("BLOCKLIST").unwrap())?;
    let port_blocklist = HashMap::try_from(bpf.map_mut("PORT_BLOCKLIST").unwrap())?;

    let shared_state = Arc::new(Mutex::new(SharedState {
        ip_blocklist,
        port_blocklist,
        known_ips: HashSet::new(),
        known_ports: HashSet::new(),
    }));

    // Handle initial blocking from command-line arguments
    if let Some(ip_address) = args.ip_address {
        let block_addr: u32 = u32::from(ip_address); // Convert Ipv4Addr to u32
        let mut state = shared_state.lock().unwrap();
        state.ip_blocklist.insert(block_addr, 0, 0)?;
        state.known_ips.insert(block_addr);
        info!("Blocking IP: {}", ip_address);
    } else {
        info!("No IP address provided to block.");
    }

    if let Some(port) = args.port {
        let mut state = shared_state.lock().unwrap();
        state.port_blocklist.insert(port, 0, 0)?;
        state.known_ports.insert(port);
        info!("Blocking Port: {}", port);
    } else {
        info!("No port number provided to block.");
    }

    // File-watching setup
    let file_path = "/tmp/blocklist.txt";
    if !Path::new(file_path).exists() {
        fs::write(file_path, "").unwrap();
    }

    let (tx, rx) = std::sync::mpsc::channel();
    let mut watcher = watcher(tx, Duration::from_secs(1))?;
    watcher.watch(file_path, RecursiveMode::NonRecursive)?;

    let state = Arc::clone(&shared_state);

    tokio::spawn(async move {
        for event in rx.iter() {
            match event {
                Ok(_) => {
                    if let Err(e) = process_file(file_path, Arc::clone(&state)) {
                        eprintln!("Error processing blocklist file: {}", e);
                    }
                }
                Err(e) => eprintln!("Watcher error: {}", e),
            }
        }
    });

    // Wait for Ctrl-C to exit the program
    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}

/// Process the blocklist file and update BPF maps
fn process_file(file_path: &str, state: Arc<Mutex<SharedState>>) -> anyhow::Result<()> {
    let contents = fs::read_to_string(file_path)?;
    let mut state = state.lock().unwrap();

    // Temporary sets to determine new entries
    let mut new_ips = HashSet::new();
    let mut new_ports = HashSet::new();

    for line in contents.lines() {
        let parts: Vec<&str> = line.trim().split_whitespace().collect();
        match parts.as_slice() {
            ["block", "ip", ip] => {
                if let Ok(ip) = ip.parse::<Ipv4Addr>() {
                    let block_addr = u32::from(ip);
                    new_ips.insert(block_addr);
                    if !state.known_ips.contains(&block_addr) {
                        state.ip_blocklist.insert(block_addr, 0, 0)?;
                        state.known_ips.insert(block_addr);
                        info!("Blocked IP: {}", ip);
                    }
                }
            }
            ["unblock", "ip", ip] => {
                if let Ok(ip) = ip.parse::<Ipv4Addr>() {
                    let block_addr = u32::from(ip);
                    if state.known_ips.remove(&block_addr) {
                        state.ip_blocklist.remove(&block_addr)?;
                        info!("Unblocked IP: {}", ip);
                    }
                }
            }
            ["block", "port", port] => {
                if let Ok(port) = port.parse::<u16>() {
                    new_ports.insert(port);
                    if !state.known_ports.contains(&port) {
                        state.port_blocklist.insert(port, 0, 0)?;
                        state.known_ports.insert(port);
                        info!("Blocked Port: {}", port);
                    }
                }
            }
            ["unblock", "port", port] => {
                if let Ok(port) = port.parse::<u16>() {
                    if state.known_ports.remove(&port) {
                        state.port_blocklist.remove(&port)?;
                        info!("Unblocked Port: {}", port);
                    }
                }
            }
            _ => {
                eprintln!("Invalid command in blocklist file: {}", line);
            }
        }
    }

    Ok(())
}
