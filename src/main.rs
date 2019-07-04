#![feature(panic_info_message)]
#![feature(abi_x86_interrupt)]
#![feature(asm)]
#![no_std] // don't link the Rust standard library
#![cfg_attr(not(test), no_main)] // disable all Rust-level entry points
#![cfg_attr(test, allow(dead_code, unused_macros, unused_imports))]

#[macro_use]
extern crate eduos_rs;

use core::panic::PanicInfo;
use core::ptr;
// use eduos_rs::arch::processor::shutdown;

/// This function is the entry point, since the linker looks for a function
/// named `_start` by default.
#[cfg(not(test))]
#[no_mangle] // don't mangle the name of this function
pub extern "C" fn _start() -> () {
	unsafe {
		asm!("mov x0, #42" :::: "volatile");
		asm!("mov x1, #1337" :::: "volatile");;
		asm!("mov sp, x1" :::: "volatile")
	;}
	unsafe { ptr::write_volatile(0x09000000 as *mut u8, 65); }
	loop{};
	// shutdown system
	// shutdown();
}

/// This function is called on panic.
#[cfg(not(test))]
#[panic_handler]
#[no_mangle]
pub fn panic(info: &PanicInfo) -> ! {
	print!("[!!!PANIC!!!] ");

	if let Some(location) = info.location() {
		print!("{}:{}: ", location.file(), location.line());
	}

	if let Some(message) = info.message() {
		print!("{}", message);
	}

	print!("\n");

	loop {}
}
