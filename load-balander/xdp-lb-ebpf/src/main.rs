#![no_std]
#![no_main]

#![allow(nonstandard_style, dead_code)]

use aya_bpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
    helpers::bpf_csum_diff,
};
use aya_log_ebpf::info;

use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::Ipv4Hdr,
};

// hardcoded container IP values. This assumes that IP addresses are in the form 172.17.0.x
const BACKEND_A: u32 = 2;
const BACKEND_B: u32 = 3;
const CLIENT: u32 = 4;
const LB: u32 = 5;

#[xdp]
pub fn xdp_lb(ctx: XdpContext) -> u32 {
    match lb(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
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
    let source = u32::from_be(unsafe { (*ipv4hdr).src_addr });
    let check = u16::from_be(unsafe { (*ipv4hdr).check });
    if(source ==  ip_address(CLIENT)){
        info!(&ctx, "received a request from client {} ", check);
        unsafe { (*ipv4hdr).dst_addr = ip_address(BACKEND_A) };
        unsafe { (*ethhdr).dst_addr[5]= BACKEND_A as u8 };

    } else {
        info!(&ctx, "request from client");
        unsafe { (*ipv4hdr).dst_addr = ip_address(CLIENT) };
        unsafe { (*ethhdr).dst_addr[5]= CLIENT as u8 };
    }

        info!(&ctx, "Changing source to LB");
        unsafe { (*ipv4hdr).dst_addr = ip_address(LB) };
        unsafe { (*ethhdr).dst_addr[5]= LB as u8 };
        let csum = iph_csum(unsafe {&mut *ipv4hdr});
        info!(&ctx, "new checksum {}", csum);
        unsafe { (*ipv4hdr).check = csum};
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
#[inline(always)]
fn ip_address(x: u32) -> u32{
    return u32::from_be((x<<24)+(0<<16)+(17<<8)+172);
}

#[inline(always)]
fn csum_fold_helper(csum: u64) -> u16 {
    let mut csum = csum;
    for _ in 0..4 {
        if csum >> 16 != 0 {
            csum = (csum & 0xffff) + (csum >> 16);
        }
    }
    (!csum).try_into().unwrap()
}
#[inline(always)]
fn iph_csum(iph: *mut Ipv4Hdr) -> u16 {
    unsafe { (*iph).check = 0};
    let mut csum = unsafe { bpf_csum_diff(core::ptr::null_mut(), 0, iph as *mut Ipv4Hdr as *mut u32, mem::size_of::<Ipv4Hdr>().try_into().unwrap(), 0) as u64 };
       for _ in 0..4 {
        if csum >> 16 != 0 {
           csum = (csum & 0xffff) + (csum >> 16);
        }
    }
    return csum as u16;
}