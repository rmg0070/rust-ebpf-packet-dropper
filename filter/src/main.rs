#![allow(warnings)]
use anyhow::{Context, Result, anyhow};
use aya::{Bpf, programs::{Xdp, XdpFlags}, include_bytes_aligned, maps::HashMap};
use aya_log::BpfLogger;
use clap::Parser;
use log::{info, warn};
use std::net::Ipv4Addr;
use tokio::{fs::File, io::{self, AsyncWriteExt, AsyncReadExt, AsyncBufReadExt, BufReader}, sync::Mutex, signal};
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use pnet::datalink;
use log4rs::{
    Config, config::{Appender, Root},
    append::file::FileAppender,
    encode::pattern::PatternEncoder,
};
use std::collections::HashSet;
use std::str::FromStr;
use std::fmt::Debug;
use std::hash::Hash;

const IP_BLOCKLIST_FILE: &str = "ip_blocklist.txt";
const PORT_BLOCKLIST_FILE: &str = "port_blocklist.txt";

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

async fn save_blocklist<T: ToString + Copy>(blocklist: &HashSet<T>, filename: &str) -> Result<()> {
    let mut file = File::create(filename).await?;
    // println!("Blocked Port:");
    for &item in blocklist {
        println!("Blocked Port: {}", item.to_string());
        file.write_all(item.to_string().as_bytes()).await?;
        file.write_all(b"\n").await?;
        // println!("Blocked Port: {}", item.to_string());
    }
    file.flush().await?;
    Ok(())
}

async fn load_blocklist<T>(filename: &str) -> Result<HashSet<T>, anyhow::Error>
where
    T: FromStr + Eq + Hash + Debug,
    <T as FromStr>::Err: Debug,
{
    let file = File::open(filename).await?;
    let mut reader = BufReader::new(file);
    let mut contents = String::new();
    reader.read_to_string(&mut contents).await?;

    let mut blocklist = HashSet::new();
    for line in contents.lines() {
        match line.parse::<T>() {
            Ok(value) => { blocklist.insert(value); },
            Err(e) => {
                warn!("Failed to parse line '{}' into type: {:?}", line, e);
            }
        }
    }
    Ok(blocklist)
}

#[tokio::main]
async fn main() -> Result<()> {
    setup_logging()?; // Initialize file logging

    let args = Args::parse(); // Parse command line arguments

    // Load initially blocked IPs and ports from files
    let mut blocked_ips = load_blocklist::<Ipv4Addr>(IP_BLOCKLIST_FILE).await?;
    let mut blocked_ports = load_blocklist::<u16>(PORT_BLOCKLIST_FILE).await?;

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

    // Add initially blocked IPs and ports to the eBPF maps
    {
        let mut blocklist: HashMap<_, u32, u32> = HashMap::try_from(bpf.map_mut("BLOCKLIST").unwrap())?;
        for ip in &blocked_ips {
            blocklist.insert(u32::from(*ip), 0, 0)?;
            info!("Added initially blocked IP: {}", ip);
        }

        let mut port_blocklist: HashMap<_, u16, u16> = HashMap::try_from(bpf.map_mut("PORT_BLOCKLIST").unwrap())?;
        for port in &blocked_ports {
            port_blocklist.insert(*port, 0, 0)?;
            info!("Added initially blocked Port: {}", port);
        }
    }

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
                        blocked_ips.insert(ip);
                        save_blocklist(&blocked_ips, IP_BLOCKLIST_FILE).await?;
                        info!("Blocked IP: {}", ip);
                    }
                },
                    "unblockip" if parts.len() == 2 => {
                    if let Ok(ip) = parts[1].parse::<Ipv4Addr>() {
                        let mut bpf = bpf_shared.lock().await;
                        let mut blocklist: HashMap<_, u32, u32> = HashMap::try_from(bpf.map_mut("BLOCKLIST").unwrap())?;

                        blocklist.remove(&u32::from(ip))?;
                        info!("Removed IP from eBPF map: {}", ip);

                        blocked_ips.remove(&ip);
                        save_blocklist(&blocked_ips, IP_BLOCKLIST_FILE).await?;
                        info!("Unblocked IP: {}", ip);
                    }
                },
                "blockport" if parts.len() == 2 => {
                    if let Ok(port) = parts[1].parse::<u16>() {
                        let mut bpf = bpf_shared.lock().await;
                        let mut port_blocklist: HashMap<_, u16, u16> = HashMap::try_from(bpf.map_mut("PORT_BLOCKLIST").unwrap())?;
                        port_blocklist.insert(port, 0, 0)?;
                        blocked_ports.insert(port);
                        save_blocklist(&blocked_ports, PORT_BLOCKLIST_FILE).await?;
                        info!("Blocked Port: {}", port);
                    }
                },
                "unblockport" if parts.len() == 2 => {
                    if let Ok(port) = parts[1].parse::<u16>() {
                        let mut bpf = bpf_shared.lock().await;
                        let mut port_blocklist: HashMap<_, u16, u16> = HashMap::try_from(bpf.map_mut("PORT_BLOCKLIST").unwrap())?;
                        port_blocklist.remove(&port)?;
                        blocked_ports.remove(&port);
                        save_blocklist(&blocked_ports, PORT_BLOCKLIST_FILE).await?;
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
    handle_task.await??; // Wait for the handle task to complete
    info!("Application exiting.");

    Ok(())
}
