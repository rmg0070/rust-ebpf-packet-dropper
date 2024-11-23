#![allow(warnings)]
use anyhow::{Context, Result, anyhow};
use aya::{Bpf, programs::{Xdp, XdpFlags}, include_bytes_aligned, maps::HashMap};
use aya_log::BpfLogger;
use clap::Parser;
use log::{info, warn};
use std::net::Ipv4Addr;
use tokio::{sync::Mutex, io::{self, AsyncBufReadExt, BufReader}, signal};
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use pnet::datalink;
use log4rs::{
    Config, config::{Appender, Root},
    append::file::FileAppender,
    encode::pattern::PatternEncoder,
};

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

fn setup_logging() -> Result<()> {
    let logfile = FileAppender::builder()
        .encoder(Box::new(PatternEncoder::new("{d} - {l} - {m}\n")))
        .build("application.log")?;

    let config = Config::builder()
        .appender(Appender::builder().build("logfile", Box::new(logfile)))
        .build(Root::builder().appender("logfile").build(log::LevelFilter::Info))?;

    log4rs::init_config(config)?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    setup_logging()?;  // Initialize file logging

    let args = Args::parse();  // Parse command line arguments

    let mut bpf = Bpf::load(include_bytes_aligned!("../../target/bpfel-unknown-none/debug/xdp-drop"))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        warn!("Failed to initialize eBPF logger: {}", e);
        return Err(e).context("Failed to initialize eBPF logger");
    }

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

    let bpf_shared = Arc::new(Mutex::new(bpf));
    let shutdown_flag = Arc::new(AtomicBool::new(false));

    let flag_clone = shutdown_flag.clone();
    let handle_task = tokio::spawn(async move {
        let mut reader = BufReader::new(io::stdin());
        let mut line = String::new();
        
        while reader.read_line(&mut line).await? > 0 {
            let trimmed_line = line.trim();
            let parts: Vec<&str> = trimmed_line.split_whitespace().collect();
            
            if parts[0] == "exit" {
                info!("Exit command received, initiating shutdown.");
                flag_clone.store(true, Ordering::Relaxed);
                break;
            }
            
            match parts[0] {
                "blockip" if parts.len() == 2 => {
                    if let Ok(ip) = parts[1].parse::<Ipv4Addr>() {
                        let mut bpf = bpf_shared.lock().await;
                        let mut blocklist: HashMap<_, u32, u32> = HashMap::try_from(bpf.map_mut("BLOCKLIST").unwrap())?;
                        blocklist.insert(u32::from(ip), 0, 0)?;
                        info!("Blocked IP: {}", ip);
                    }
                },
                "unblockip" if parts.len() == 2 => {
                    if let Ok(ip) = parts[1].parse::<Ipv4Addr>() {
                        let mut bpf = bpf_shared.lock().await;
                        let mut blocklist: HashMap<_, u32, u32> = HashMap::try_from(bpf.map_mut("BLOCKLIST").unwrap())?;
                        blocklist.remove(&u32::from(ip))?;
                        info!("Unblocked IP: {}", ip);
                    }
                },
                "blockport" if parts.len() == 2 => {
                    if let Ok(port) = parts[1].parse::<u16>() {
                        let mut bpf = bpf_shared.lock().await;
                        let mut port_blocklist: HashMap<_, u16, u16> = HashMap::try_from(bpf.map_mut("PORT_BLOCKLIST").unwrap())?;
                        port_blocklist.insert(port, 0, 0)?;
                        info!("Blocked Port: {}", port);
                    }
                },
                "unblockport" if parts.len() == 2 => {
                    if let Ok(port) = parts[1].parse::<u16>() {
                        let mut bpf = bpf_shared.lock().await;
                        let mut port_blocklist: HashMap<_, u16, u16> = HashMap::try_from(bpf.map_mut("PORT_BLOCKLIST").unwrap())?;
                        port_blocklist.remove(&port)?;
                        info!("Unblocked Port: {}", port);
                    }
                },
                _ => warn!("Unknown command or incorrect number of arguments"),
            }
            line.clear();
        }
        Ok::<(), anyhow::Error>(())
    });

    signal::ctrl_c().await?;
    handle_task.await??;  // Wait for the handle task to complete
    info!("Application exiting.");

    Ok(())
}
