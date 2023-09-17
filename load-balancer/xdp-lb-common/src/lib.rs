#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Registry {
    pub ip: [u32; 4],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Registry {}
