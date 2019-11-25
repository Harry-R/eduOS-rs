// Copyright (c) 2017-2018 Stefan Lankes, RWTH Aachen University
// Copyright (c) 2019 Leonard Rapp, RWTH Aachen University
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Architecture dependent interface to initialize a task

use core::mem::size_of;
use scheduler::task::*;
use scheduler::{do_exit,get_current_taskid};
use consts::*;
use logging::*;
use compiler_builtins::mem::memset;
use core::ptr;
use logging::*;

#[derive(Debug)]
#[repr(C)]
pub struct State {
    elr_el1: u64,
	spsr_el1: u64,
	x0: u64,
	x1: u64,
	x2: u64,
	x3: u64,
	x4: u64,
	x5: u64,
	x6: u64,
	x7: u64,
	x8: u64,
	x9: u64,
	x10: u64,
	x11: u64,
	x12: u64,
	x13: u64,
	x14: u64,
	x15: u64,
	x16: u64,
	x17: u64,
	x18: u64,
	x19: u64,
	x20: u64,
	x21: u64,
	x22: u64,
	x23: u64,
	x24: u64,
	x25: u64,
	x26: u64,
	x27: u64,
	x28: u64,
	x29: u64,
	x30: u64,
	x31: u64, // alias sp or xzr (depends on the instruction)
}

pub extern "C" fn leave_task() {
	do_exit();
	loop {
	}
}

extern "C" fn enter_task(func: extern fn()) {
	func();
	leave_task();
}

impl TaskFrame for Task {
	// TODO: further changes for aarch64
    fn create_stack_frame(&mut self, func: extern fn())
	{
		unsafe {
			// create aligned stack
			let aligned_stack = (*self.stack).top() & !0xFFusize;
			let mut stack: *mut u64 = aligned_stack as *mut u64;

			// save space for storing task state
			stack = (stack as usize - size_of::<State>()) as *mut u64;
			let state: *mut State = stack as *mut State;
			ptr::write_bytes(state, 0, 1);

			//
			(*state).elr_el1 = (enter_task as *const()) as u64;
			(*state).spsr_el1 = 0x205u64;
			(*state).x0 = (func as *const()) as u64;
			(*state).x30 = (leave_task as *const()) as u64;

			/* Set the task's stack pointer entry to the stack we have crafted right now. */
			self.last_stack_pointer =  state as usize;
		}
	}
}
