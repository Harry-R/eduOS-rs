#![no_std]
use logging::*;
/// Some space for init stuff before calling `main()`.
#[no_mangle]
pub unsafe extern "C" fn init() -> ! {
    info!("Jumped to Rust code");
    // nothing to initialize atm

    extern "Rust" {
        fn main() -> !;
    }

   main();
}

// Disable all cores except core 0, and then jump to init()
global_asm!(include_str!("boot.S"));