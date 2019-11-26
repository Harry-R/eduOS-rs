// Copyright (c) 2019 Leonard Rapp, RWTH Aachen University
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
use super::irq::unmask_cntp_el0;

#[no_mangle]
/// Initialize physical EL1 timer
/// * `tval` - ticks until the timer should trigger
pub fn set_tval(tval: u32) {
    unmask_cntp_el0(false);
    // unmask timer interrupt, start timer
    let mask = 0b01;
    unsafe { asm!("msr cntp_ctl_el0, x7" :: "{x7}"(mask) :"x7":) }
    // set tval (time until timer triggers)
    unsafe { asm!("msr cntp_tval_el0, x7" :: "{x7}"(tval) :"x7":) }
    unmask_cntp_el0(true);
}
