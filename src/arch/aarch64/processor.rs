#![allow(dead_code)]
#[no_mangle]

pub fn halt() {
	// TODO: implement halt for aarch64
	unsafe {
		asm!("mov x1, x1");
	}
}

#[no_mangle]
pub extern "C" fn shutdown() -> ! {
	// TODO: implement
	println!("UNIMPLEMENTED!");
	loop{
		halt();
	};
}


pub fn init() {
	// TODO: what to implement here? redundant to boot.rs? Structure should by like for x86_64.
}
