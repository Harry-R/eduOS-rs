#![no_std]

/// Some space for init stuff before calling `main()`.
#[no_mangle]
pub unsafe extern "C" fn init() -> ! {

    // nothing to initialize atm

    extern "Rust" {
        fn main() -> !;
        fn irq_enable();
    }

    irq_enable();
    main();
}

// Disable all cores except core 0, and then jump to init()
global_asm!(include_str!("boot.S"));