

#![no_std]
#![no_main]
#![allow(nonstandard_style, dead_code)]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};
use aya_log_ebpf::info;

use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::Ipv4Hdr,
    tcp::TcpHdr,
    udp::UdpHdr,
};

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

// IP blocklist map
#[map]
static BLOCKLIST: HashMap<u32, u32> = HashMap::<u32, u32>::with_max_entries(1024, 0);

// Port blocklist map
#[map]
static PORT_BLOCKLIST: HashMap<u16, u16> = HashMap::<u16, u16>::with_max_entries(1024, 0);

#[xdp]
pub fn xdp_firewall(ctx: XdpContext) -> u32 {
    match try_xdp_firewall(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    // Ensure the access is within bounds
    if start + offset + len > end {
        return Err(());
    }

    let ptr = (start + offset) as *const T;
    Ok(ptr)
}

// IP blocking function
fn block_ip_fn(ctx: &XdpContext, source: u32) -> u32 {
    if block_ip(source) {
        info!(ctx, "Blocking IP: {:i}", source);
        return xdp_action::XDP_DROP;
    }
    xdp_action::XDP_PASS
}

// Port blocking function
fn block_port_fn(ctx: &XdpContext, protocol: u8, ctx_offset: usize) -> u32 {
    match protocol {
        6 => {  // TCP protocol number
            if let Ok(tcphdr) = unsafe { ptr_at::<TcpHdr>(ctx, ctx_offset) } {
                let dest_port = u16::from_be(unsafe { (*tcphdr).dest });
                if block_port(dest_port) {
                    info!(ctx, "Blocking TCP port: {}", dest_port);
                    return xdp_action::XDP_DROP;
                }
            } else {
                return xdp_action::XDP_PASS; // Invalid access, pass the packet
            }
        },
        17 => { // UDP protocol number
            if let Ok(udphdr) = unsafe { ptr_at::<UdpHdr>(ctx, ctx_offset) } {
                let dest_port = u16::from_be(unsafe { (*udphdr).dest });
                if block_port(dest_port) {
                    info!(ctx, "Blocking UDP port: {}", dest_port);
                    return xdp_action::XDP_DROP;
                }
            } else {
                return xdp_action::XDP_PASS; // Invalid access, pass the packet
            }
        },
        _ => return xdp_action::XDP_PASS, // Allow other protocols
    }
    xdp_action::XDP_PASS
}

// Check if an IP is in the blocklist
fn block_ip(address: u32) -> bool {
    unsafe { BLOCKLIST.get(&address).is_some() }
}

// Check if a port is in the blocklist
fn block_port(port: u16) -> bool {
    unsafe { PORT_BLOCKLIST.get(&port).is_some() }
}

// ebpf port and ipblock logic
fn try_xdp_firewall(ctx: XdpContext) -> Result<u32, ()> {
    // Parse the Ethernet header
    let ethhdr: *const EthHdr = unsafe { ptr_at(&ctx, 0)? };
    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}, // Continue processing if IPv4
        _ => return Ok(xdp_action::XDP_PASS), // Pass non-IPv4 packets
    }

    // Parse the IPv4 header
    let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };
    let source = u32::from_be(unsafe { (*ipv4hdr).src_addr });

    // Ensure packet contains the protocol information
    let protocol: u8 = unsafe { *((ipv4hdr as *const u8).add(9)) };

    // Check if IP should be blocked
    let action = block_ip_fn(&ctx, source);
    if action == xdp_action::XDP_DROP {
        return Ok(action);
    }

    // If IP is not blocked, check port blocking logic
    let action = block_port_fn(&ctx, protocol, EthHdr::LEN + Ipv4Hdr::LEN);
    Ok(action)
}


