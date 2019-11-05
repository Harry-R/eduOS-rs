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

#[derive(Debug)]
#[repr(C, packed)]
struct State {
    cpsr: u64,
	pc: u64,
	sp: u64,
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

/*
	/// X0 register
	x0: u64,
	/// X1 register
	x1: u64,
	/// X2 register
	x2: u64,
	/// X3 register
	x3: u64,
	/// X4 register
	x4: u64,
	/// X5 register
	x5: u64,
	/// X6 register
	x6: u64,
	/// X7 register
	x7: u64,
	/// X8 register
	x8: u64,
	/// X9 register
	x9: u64,
	/// X10 register
	x10: u64,
	/// X11 register
	x11: u64,
	/// X12 register
	x12: u64,
	/// X13 register
	x13: u64,
	/// X14 register
	x14: u64,
	/// X15 register
	x15: u64,
	/// X16 register
	x16: u64,
	/// X17 register
	x17: u64,
	/// X18 register
	x18: u64,
	/// X19 register
	x19: u64,
	/// X10 register
	x20: u64,
	/// X21 register
	x21: u64,
	/// X22 register
	x22: u64,
	/// X23 register
	x23: u64,
	/// X24 register
	x24: u64,
	/// X25 register
	x25: u64,
	/// X26 register
	x26: u64,
	/// X27 register
	x27: u64,
	/// X28 register
	x28: u64,
	/// X29 register
	x29: u64,
	/// X30 register
	x30: u64,
	/// (pseudo) SP register,
	sp: u64,
	/// Program Counter
	pc: u64,
	/// status flags
	cpsr: u64,
*/
}

extern "C" fn leave_task() {
	debug!("finish task {}", get_current_taskid());

	do_exit();

	loop {}
}

impl TaskFrame for Task {
	// TODO: further changes for aarch64
    fn create_stack_frame(&mut self, func: extern fn())
	{
		unsafe {
			let mut stack: *mut u64 = ((*self.stack).top()) as *mut u64;

			memset((*self.stack).bottom() as *mut u8, 0xCD, STACK_SIZE);

			/* Only marker for debugging purposes, ... */
			*stack = 0xDEADBEEFu64;
			stack = (stack as usize - size_of::<u64>()) as *mut u64;

			/* the first-function-to-be-called's arguments, ... */
			//TODO: add arguments

			/* and the "caller" we shall return to.
	 		 * This procedure cleans the task after exit. */
			*stack = (leave_task as *const()) as u64;
			stack = (stack as usize - size_of::<State>()) as *mut u64;

			let state: *mut State = stack as *mut State;
			memset(state as *mut u8, 0x00, size_of::<State>());

			(*state).sp = (stack as usize + size_of::<State>()) as u64;
			(*state).x29 = (*state).sp + size_of::<u64>() as u64;

			(*state).pc = (func as *const()) as u64;;
			// TODO: Check, if we can use cpsr in the same way as rflags
			(*state).cpsr = 0x1002u64;

			/* Set the task's stack pointer entry to the stack we have crafted right now. */
			self.last_stack_pointer =  stack as usize;
		}
	}
}
