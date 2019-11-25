#![feature(asm, const_fn, lang_items, global_asm)]
#![feature(allocator_api)]
#![feature(naked_functions)]
#![no_std]

extern crate alloc;
extern crate spin;
#[cfg(target_arch = "x86_64")]
extern crate x86;

#[cfg(target_arch = "aarch64")]
extern crate aarch64;

// These need to be visible to the linker, so we need to export them.
#[cfg(target_arch = "x86_64")]
pub use arch::processor::*;
pub use logging::*;

#[macro_use]
pub mod macros;
#[macro_use]
pub mod logging;
pub mod arch;
pub mod collections;
pub mod console;
pub mod consts;
pub mod mm;
pub mod scheduler;

#[global_allocator]
static ALLOCATOR: &'static mm::allocator::Allocator = &mm::allocator::Allocator;
