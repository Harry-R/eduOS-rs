//! A wrapper around our serial console.

use arch::serial;
use core::fmt;
use spin::Mutex;

pub struct Console;

/// Specialized Rust `fmt::Write` implementation for our console
impl fmt::Write for Console {
    /// Output a string to each of our console outputs.
    fn write_str(&mut self, s: &str) -> fmt::Result {
        serial::COM1.lock().write_str(s)
    }
}

/// Console mutex
pub static CONSOLE: Mutex<Console> = Mutex::new(Console);
