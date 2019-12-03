#![allow(dead_code)]
#[no_mangle]
use logging::*;

/// halt function
pub fn halt() {
    // TODO: implement halt for aarch64
    unsafe {
        asm!("mov x1, x1");
    }
}

/// Interface for shutdown function
#[no_mangle]
pub extern "C" fn shutdown() {
    info!{"Shutdown system!"}
    unsafe { _shutdown() }
}

extern "C" {
    fn _shutdown();
}

pub fn init() {
    // TODO: what to implement here? redundant to boot.rs? Structure should by like for x86_64.
}
