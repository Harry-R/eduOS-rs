// Copyright (c) 2019 Leonard Rapp, RWTH Aachen University
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#[no_mangle]
pub fn timer_init() {
    println!("------------- Initialize timer ---------");

	let mask = 0b01;
	unsafe { asm!("msr cntp_ctl_el0, x7" :: "{x7}"(mask) :"x7":)}

    let mut outmask = 0b101010;
    unsafe { asm!("mrs x7, cntp_ctl_el0" :"={x7}"(outmask) ::"x7":)}
    println!("Current ctl is: 0b{:b}", outmask);

    let t_in = 123456;
	unsafe { asm!("msr cntp_tval_el0, x7" :: "{x7}"(t_in) :"x7":)}

    let mut t_out : i32;

    for i in 0..10 {
        unsafe { asm!("mrs x7, cntp_tval_el0" : "={x7}"(t_out)::"x7":"volatile") }
        println!("Current tval is: {}", t_out);
        unsafe { asm!("mrs x7, cntp_ctl_el0" :"={x7}"(outmask) ::"x7":)}
        println!("Current ctl is: 0b{:b}", outmask);
    }
}