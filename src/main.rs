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
use eduos_rs::arch::processor::{shutdown,halt};
use eduos_rs::scheduler;

extern "C" fn foo() {
	for _i in 0..5 {
		println!("hello from task {}", scheduler::get_current_taskid());
		scheduler::reschedule();
	}
}

/// This is the main function called by `init()` function from boot.rs
#[cfg(not(test))]
#[no_mangle] // don't mangle the name of this function
pub extern "C" fn main() {

	println!("Hello from eduOS-rs!");

	scheduler::init();

	for _i in 0..2 {
		scheduler::spawn(foo);
	}

	// send el1 sync exception with resched_int
	unsafe{asm!("svc 1" : : : )};

	println!("Shutdown system!");

	// shutdown system
	shutdown();
}

/// This function is called on panic.
#[cfg(not(test))]
#[panic_handler]
pub fn panic(info: &PanicInfo) -> ! {
	print!("[!!!PANIC!!!] ");

	if let Some(location) = info.location() {
		print!("{}:{}: ", location.file(), location.line());
	}

	if let Some(message) = info.message() {
		print!("{}", message);
	}

	print!("\n");

	loop {
		halt();
	}
}