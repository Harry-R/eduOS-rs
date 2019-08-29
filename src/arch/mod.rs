// Copyright (c) 2017 Stefan Lankes, RWTH Aachen University
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

// Export our platform-specific modules.
#[cfg(target_arch="x86_64")]
pub use self::x86_64::{serial,processor};

// Export our platform-specific modules.
#[cfg(target_arch="x86_64")]
pub use self::x86_64::switch::switch;

#[cfg(target_arch="aarch64")]
pub use self::aarch64::{serial, processor};
#[cfg(target_arch="aarch64")]
pub use self::aarch64::switch::switch;

// Implementations for x86_64.
#[cfg(target_arch="x86_64")]
pub mod x86_64;

// Implementations for aarch64.
#[cfg(target_arch="aarch64")]
pub mod aarch64;