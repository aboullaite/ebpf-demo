#![no_std]
#![no_main]

#![allow(nonstandard_style, dead_code)]

use aya_bpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
    helpers::{bpf_csum_diff, bpf_l3_csum_replace},
};
use aya_log_ebpf::info;

use core::{mem, ptr};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::Ipv4Hdr,
    tcp::TcpHdr,
};

// hardcoded container IP values. This assumes that IP addresses are in the form 172.17.0.x
const BACKEND_A: u32 = 2;
const BACKEND_B: u32 = 3;
const CLIENT: u32 = 5;
const LB: u32 = 4;

#[xdp]
pub fn xdp_lb(ctx: XdpContext) -> u32 {
    match lb(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_DROP,
    }
}

fn lb(ctx: XdpContext) -> Result<u32, u32> {
    info!(&ctx, "received a packet");
    
    let ethhdr: *mut EthHdr = unsafe { ptr_at_mut(&ctx, 0).ok_or(xdp_action::XDP_DROP)? };
    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_DROP),
    }
    info!(&ctx, "received a eth packet");
    let ipv4hdr: *mut Ipv4Hdr = unsafe { ptr_at_mut(&ctx, EthHdr::LEN).ok_or(xdp_action::XDP_DROP)? };
    info!(&ctx, "received a ipv4 packet");

    let tcphdr: *mut TcpHdr = unsafe {ptr_at_mut(&ctx, EthHdr::LEN + Ipv4Hdr::LEN).ok_or(xdp_action::XDP_DROP)?};
    let source = u32::from_be(unsafe { (*ipv4hdr).src_addr });
    let dest = u32::from_be(unsafe { (*ipv4hdr).dst_addr });
    let check = unsafe { (*ipv4hdr).check };
    info!(&ctx, "checksum initial {}, source {}, destination {}", check, source, dest);
    if(source ==  ip_address(CLIENT)){
        info!(&ctx, "received a request from client ");
        unsafe { (*ipv4hdr).dst_addr = ip_address2(BACKEND_A) };
        unsafe { (*ethhdr).dst_addr[5]=BACKEND_A as u8 };

    } else {
        info!(&ctx, "request not from from client");
        unsafe { (*ipv4hdr).dst_addr = ip_address2(CLIENT) };
        unsafe { (*ethhdr).dst_addr[5]= CLIENT as u8 };
    }

    //     info!(&ctx, "Changing source to LB {}", ip_address(LB));
        unsafe { (*ipv4hdr).src_addr = ip_address2(LB) };
        unsafe { (*ethhdr).src_addr[5]= LB as u8 };

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
        // unsafe { (*ipv4hdr).check = csum_fold_helper(full_cksum) };
        // unsafe { (*tcphdr).check = 0 };
        // let checksum = unsafe { bpf_csum_diff(ptr::null_mut() as *mut u32, 0, &mut *ipv4hdr as *mut Ipv4Hdr as *mut u32, mem::size_of_val(&ipv4hdr) as u32, 0)} as u32;
        // // bpf_csum_diff returns a checksum on 32-bits, so we need to fold it back to 16 bits
        let source = u32::from_be(unsafe { (*ipv4hdr).src_addr });
        let dest = u32::from_be(unsafe { (*ipv4hdr).dst_addr });
        let check = unsafe { (*ipv4hdr).check };
        let eth = unsafe { (*ethhdr).dst_addr};
        info!(&ctx, "Mac {},{},{},{},  {},  {}", eth[0],eth[1],eth[2],eth[3], eth[4], eth[5]);

        info!(&ctx, "checksum final {}, source {}, destination {}", check, source, dest);

        // let csum = csum_fold_helper(checksum);
        // info!(&ctx, "new checksum {}", csum);
        // unsafe { (*ipv4hdr).check = !csum};
        // unsafe { (*ipv4hdr).check = 22616 };
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

fn ip_address2(x: u32) -> u32{
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