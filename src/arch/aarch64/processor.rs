#![allow(dead_code)]
#[no_mangle]
use logging::*;

pub fn halt() {
	// TODO: implement halt for aarch64
	unsafe {
		asm!("mov x1, x1");
	}
}

#[no_mangle]
pub extern "C" fn shutdown(){
	info!("Shutdown system!");
	unsafe {_shutdown()}
}

extern "C" {
	fn _shutdown();
}

