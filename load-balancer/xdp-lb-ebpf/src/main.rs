#![no_std]
#![no_main]

#![allow(nonstandard_style, dead_code)]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::Array,
    programs::XdpContext,
    helpers::{bpf_csum_diff, bpf_ktime_get_ns},
};

use aya_log_ebpf::info;
use core::{mem};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::Ipv4Hdr,
    tcp::TcpHdr,
};

// hardcoded container IP values. This assumes that IP addresses are in the form 172.17.0.x
const CLIENT: u8 = 18;
const LB: u8 = 15;

#[map] 
static BACKENDS: Array<u32> = Array::<u32>::with_max_entries(10, 0);
   
#[xdp]
pub fn xdp_lb(ctx: XdpContext) -> u32 {
    match lb(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_DROP,
    }
}

fn lb(ctx: XdpContext) -> Result<u32, u32> {
    info!(&ctx, "received a packet");
    
    unsafe {
    let ethhdr: *mut EthHdr = ptr_at_mut(&ctx, 0).ok_or(xdp_action::XDP_ABORTED)?;
    match (*ethhdr).ether_type  {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }
    let ipv4hdr: *mut Ipv4Hdr = ptr_at_mut(&ctx, EthHdr::LEN).ok_or(xdp_action::XDP_ABORTED)?;

    let tcphdr: *mut TcpHdr = ptr_at_mut(&ctx, EthHdr::LEN + Ipv4Hdr::LEN).ok_or(xdp_action::XDP_PASS)?;
    let source = (*ipv4hdr).src_addr ;
    let dest = (*ipv4hdr).dst_addr ;
    let initial_csum = (*ipv4hdr).check ;
    info!(&ctx, "Request coming from {} to {}, checksum {}", source, dest, initial_csum);
    // get random ip
    let random = (bpf_ktime_get_ns() as u32) % 2;

    // Extract backend logic
    let backend = match BACKENDS.get(random) {
        Some(backend) => { *backend }
        None => {
            info!(&ctx, "No backends found!");
            return Ok(xdp_action::XDP_PASS);
        }
    };

    info!(&ctx, "Forwarding request to IP 10.0.4.{}", backend);

    if source ==  ip_address(CLIENT) {
        info!(&ctx, "Got request from client");
        (*ethhdr).dst_addr[5]= backend as u8;
        (*ipv4hdr).dst_addr = ip_address(backend as u8) ;

    } else {
        info!(&ctx, "Got request not from client");
        (*ethhdr).dst_addr[5]= CLIENT;
        (*ipv4hdr).dst_addr = ip_address(CLIENT);
    }
        (*ethhdr).src_addr[5]= LB;
        (*ipv4hdr).src_addr = ip_address(LB) ;
        
        // unsafe { (*tcphdr).source = (*tcphdr).dest };

        let csum = !((*ipv4hdr).check as u32);
        let csum = bpf_csum_diff(&source as *const u32 as *mut u32, 4, &(*ipv4hdr).src_addr as *const u32 as *mut u32, 4, csum) as u32;
        let csum = bpf_csum_diff(&dest as *const u32 as *mut u32, 4, &(*ipv4hdr).dst_addr as *const u32 as *mut u32, 4, csum) as u32;
        unsafe { (*ipv4hdr).check = csum_fold(csum) } ;
        
        // Debugging info
        let source = unsafe { (*ipv4hdr).src_addr };
        let dest = unsafe { (*ipv4hdr).dst_addr };
        let check = unsafe { (*ipv4hdr).check };

        info!(&ctx, "final checksum {}, source {}, destination {}", check, source, dest);
    }
        Ok(xdp_action::XDP_TX)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Option<*const T> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return None;
    }

    Some((start + offset) as *const T)
}

#[inline(always)]
fn ptr_at_mut<T>(ctx: &XdpContext, offset: usize) -> Option<*mut T> {
    let ptr = ptr_at::<T>(ctx, offset)?;
    Some(ptr as *mut T)
}

fn ip_address(x: u8) -> u32 {
    u32::from_be_bytes([10, 0, 4, x]).to_be()
}

#[inline(always)]
fn csum_fold(mut csum: u32) -> u16 {
    csum = (csum & 0xffff) + (csum >> 16);
    csum = !((csum & 0xffff) + (csum >> 16));
    csum as u16
}