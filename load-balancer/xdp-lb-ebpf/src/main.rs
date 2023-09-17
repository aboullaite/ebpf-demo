#![no_std]
#![no_main]

#![allow(nonstandard_style, dead_code)]

use aya_bpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
    helpers::{bpf_csum_diff, bpf_skb_store_bytes},
};
use xdp_lb_common::Registry;
use aya_log_ebpf::info;
use core::{mem, ptr};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::Ipv4Hdr,
    tcp::TcpHdr,
};

use rand::{Rng, SeedableRng};
use rand::rngs::SmallRng;
use rand::RngCore;

// hardcoded container IP values. This assumes that IP addresses are in the form 172.17.0.x
const CLIENT: u32 = 5;
const LB: u32 = 4;

#[map] 
static BACKENDS: HashMap<&str, Registry> =
    HashMap::<&str, Registry>::with_max_entries(10, 0);
   
#[xdp]
pub fn xdp_lb(ctx: XdpContext) -> u32 {
    match lb(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_DROP,
    }
}

fn lb(ctx: XdpContext) -> Result<u32, u32> {
    info!(&ctx, "received a packet");
    
    let ethhdr: *mut EthHdr = unsafe { ptr_at_mut(&ctx, 0).ok_or(xdp_action::XDP_ABORTED)? };
    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }
    let ipv4hdr: *mut Ipv4Hdr = unsafe { ptr_at_mut(&ctx, EthHdr::LEN).ok_or(xdp_action::XDP_ABORTED)? };

    let tcphdr: *mut TcpHdr = unsafe {ptr_at_mut(&ctx, EthHdr::LEN + Ipv4Hdr::LEN).ok_or(xdp_action::XDP_PASS)?};
    let source = unsafe { (*ipv4hdr).src_addr.to_be() };
    let dest = unsafe { (*ipv4hdr).dst_addr.to_be() };
    let check = unsafe { (*ipv4hdr).check.to_be() };

    // Extract backend logic
    let backends = match unsafe { BACKENDS.get("BACKENDS") } {
        Some(backends) => {backends}
        None => {
            info!(&ctx, "NO backends found");
            return Ok(xdp_action::XDP_PASS);
        }
    };
    if backends.index > backends.ips.len() - 1 {
        info!(&ctx, "Backend list is empty!");
        return Ok(xdp_action::XDP_PASS);
    }
    // get random ip
    let mut small_rng = SmallRng::seed_from_u64(backends.len());
    let new_dest = backends[small_rng.next_u64() as u32];

    if(source ==  ip_address(CLIENT)){
        unsafe { (*ipv4hdr).dst_addr = ip_address(new_dest) };
        unsafe { (*ethhdr).dst_addr[5]= new_dest as u8 };

    } else {
        unsafe { (*ipv4hdr).dst_addr = ip_address(CLIENT) };
        unsafe { (*ethhdr).dst_addr[5]= CLIENT as u8 };
    }

        unsafe { (*ipv4hdr).src_addr = ip_address(LB) };
        unsafe { (*ethhdr).src_addr[5]= LB as u8 };
        unsafe { (*tcphdr).source = (*tcphdr).dest };


        unsafe { (*ipv4hdr).check = 0 };
        let full_cksum = unsafe {
            bpf_csum_diff(
                mem::MaybeUninit::zeroed().assume_init(),
                0,
                ipv4hdr as *mut u32,
                mem::size_of::<Ipv4Hdr>() as u32,
                0,
            )
        } as u64;
        unsafe { (*ipv4hdr).check = csum_fold_helper(full_cksum) };
        unsafe { (*tcphdr).check = 0 };
        let source = u32::from_be(unsafe { (*ipv4hdr).src_addr });
        let dest = u32::from_be(unsafe { (*ipv4hdr).dst_addr });
        let check = unsafe { (*ipv4hdr).check };

        let eth: *mut EthHdr = unsafe { ptr_at_mut(&ctx, 0).ok_or(xdp_action::XDP_ABORTED)? };
        let debug =  unsafe { (*eth).dst_addr[5] };
        info!(&ctx, "checksum final {}, source {}, destination {}", check, source, debug);

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
    info!(ctx, "PArsing ...", );

    let ptr = ptr_at::<T>(ctx, offset)?;
    Some(ptr as *mut T)
}
// #[inline(always)]
// fn ip_address(x: u32) -> u32{
//     return u32::from_be((x<<24)+(0<<16)+(17<<8)+172);
// }
#[inline(always)]
fn ip_address(x: u32) -> u32{
    return (x<<24)+(0<<16)+(17<<8)+172;
}

// Converts a checksum into u16
#[inline(always)]
pub fn csum_fold_helper(mut csum: u64) -> u16 {
    for _i in 0..4 {
        if (csum >> 16) > 0 {
            csum = (csum & 0xffff) + (csum >> 16);
        }
    }
    return !(csum as u16);
}