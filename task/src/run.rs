#![allow(warnings)]

// use std::process::Command;
// use std::net::Ipv4Addr;
// use anyhow::Context as _;
// use clap::Parser;

// use crate::build_ebpf::{build_ebpf, Architecture, Options as BuildOptions};

// #[derive(Debug, Parser)]
// pub struct Options {
//     /// Set the endianness of the BPF target
//     #[clap(default_value = "bpfel-unknown-none", long)]
//     pub bpf_target: Architecture,
//     /// Build and run the release target
//     #[clap(long)]
//     pub release: bool,
//     /// The command used to wrap your application
//     #[clap(short, long, default_value = "sudo -E")]
//     pub runner: String,
//     /// Arguments to pass to your application
//     #[clap(name = "args", last = true)]
//     pub run_args: Vec<String>,
//     /// IP address to be blocked
//     #[clap(long)]
//     pub ip_address: Ipv4Addr,
// }

// /// Build the project
// fn build(opts: &Options) -> Result<(), anyhow::Error> {
//     let mut args = vec!["build"];
//     if opts.release {
//         args.push("--release");
//     }
//     let status = Command::new("cargo")
//         .args(&args)
//         .status()
//         .expect("failed to build userspace");
//     assert!(status.success());
//     Ok(())
// }

// /// Build and run the project
// pub fn run(mut opts: Options) -> Result<(), anyhow::Error> {
//     // Build the eBPF program followed by our application
//     build_ebpf(BuildOptions {
//         target: opts.bpf_target,
//         release: opts.release,
//     })
//     .context("Error while building eBPF program")?;
//     build(&opts).context("Error while building userspace application")?;

//     // Profile we are building (release or debug)
//     let profile = if opts.release { "release" } else { "debug" };
//     let bin_path = format!("target/{profile}/xdp-drop");

//     // Correct argument format: --ip-address
//     opts.run_args.push(format!("--ip-address={}", opts.ip_address));

//     // Convert run_args from Vec<String> to Vec<&str>
//     let mut run_args: Vec<_> = opts.run_args.iter().map(String::as_str).collect();

//     // Configure args
//     let mut args: Vec<_> = opts.runner.trim().split_terminator(' ').collect();
//     args.push(bin_path.as_str());
//     args.append(&mut run_args);

//     // Run the command
//     let status = Command::new(args.first().expect("No first argument"))
//         .args(args.iter().skip(1))
//         .status()
//         .expect("failed to run the command");

//     if !status.success() {
//         anyhow::bail!("Failed to run `{}`", args.join(" "));
//     }
//     Ok(())
// }
use std::process::Command;
use std::net::Ipv4Addr;
use anyhow::{Context, Result, bail};
use clap::Parser;

use crate::build_ebpf::{build_ebpf, Architecture, Options as BuildOptions};

#[derive(Debug, Parser)]
pub struct Options {
    /// Set the endianness of the BPF target
    #[clap(default_value = "bpfel-unknown-none", long)]
    pub bpf_target: Architecture,
    /// Build and run the release target
    #[clap(long)]
    pub release: bool,
    /// The command used to wrap your application
    #[clap(short, long, default_value = "sudo -E")]
    pub runner: String,
    /// Arguments to pass to your application
    #[clap(name = "args", last = true)]
    pub run_args: Vec<String>,
    /// IP address to be blocked, optional
    #[clap(long)]
    pub ip_address: Option<Ipv4Addr>,
    /// Port number to be blocked, optional
    #[clap(long)]
    pub port: Option<u16>,
}

/// Build the project
fn build(opts: &Options) -> Result<()> {
    let mut args = vec!["build"];
    if opts.release {
        args.push("--release");
    }
    let status = Command::new("cargo")
        .args(&args)
        .status()
        .context("Failed to build userspace")?;
    assert!(status.success());
    Ok(())
}

/// Build and run the project
pub fn run(mut opts: Options) -> Result<()> {
    // Build the eBPF program followed by our application
    build_ebpf(BuildOptions {
        target: opts.bpf_target,
        release: opts.release,
    })
    .context("Error while building eBPF program")?;
    build(&opts).context("Error while building userspace application")?;

    // Profile we are building (release or debug)
    let profile = if opts.release { "release" } else { "debug" };
    let bin_path = format!("target/{profile}/xdp-drop");

    // Add IP address to run arguments if provided
    if let Some(ip) = opts.ip_address {
        opts.run_args.push(format!("--ip-address={}", ip));
    }
    // Add port to run arguments if provided
    if let Some(port) = opts.port {
        opts.run_args.push(format!("--port={}", port));
    }

    // Convert run_args from Vec<String> to Vec<&str>
    let mut run_args: Vec<_> = opts.run_args.iter().map(String::as_str).collect();

    // Configure args
    let mut args: Vec<_> = opts.runner.trim().split_terminator(' ').collect();
    args.push(bin_path.as_str());
    args.append(&mut run_args);

    // Run the command
    let status = Command::new(args.first().expect("No first argument"))
        .args(args.iter().skip(1))
        .status()
        .context("Failed to run the command")?;

    if !status.success() {
        bail!("Failed to run `{}`", args.join(" "));
    }
    Ok(())
}
