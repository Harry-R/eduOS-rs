// Copyright (c) 2017 Stefan Lankes, RWTH Aachen University
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

#![allow(dead_code)]
#![allow(private_no_mangle_fns)]

//! Interface to the scheduler

use consts::*;
use synch::spinlock::*;
use alloc::{Vec,VecDeque};

/// task control block
pub mod task;
mod scheduler;

static mut SCHEDULER: SpinlockIrqSave<scheduler::Scheduler> = SpinlockIrqSave::new(scheduler::Scheduler::new());

extern {
	/// The boot loader initialize a stack, which is later also required to
	/// to boot other core. Consequently, the kernel has to replace with this
	/// function the boot stack by a new one.
	pub fn replace_boot_stack(stack_bottom: usize);
}

/// Initialite module, must be called once, and only once
pub fn init() {
	// initialize vector of queues
	let mut veq_queue = Vec::with_capacity(NO_PRIORITIES as usize);
	for _i in 0..NO_PRIORITIES {
		veq_queue.push(VecDeque::with_capacity(MAX_TASKS));
	}

	unsafe {
		// boot task is implicitly task 0 and and the idle task of core 0
		let mut sched = SCHEDULER.lock();
		sched.task_table[0].status = task::TaskStatus::TaskIdle;
		sched.task_table[0].id = task::TaskId::from(0);
		sched.ready_queues = Some(veq_queue);

		// replace temporary boot stack by the kernel stack of the boot task
		replace_boot_stack(sched.task_table[0].stack.bottom());
	}
}

/// Create a new kernel task
#[inline(always)]
pub fn spawn(func: extern fn(), prio: task::Priority) -> Result<task::TaskId, scheduler::SchedulerError> {
	unsafe {
		let mut sched = SCHEDULER.lock();
		sched.spawn(func, prio)
	}
}

/// Trigger the scheduler to switch to the next available task
#[inline(always)]
pub fn reschedule() {
	unsafe {
		let mut sched = SCHEDULER.lock();
		sched.reschedule()
	}
}

/// Set current task status to TaskBlocked
#[inline(always)]
pub fn block_current_task() {
	unsafe {
		let mut sched = SCHEDULER.lock();
		sched.block_current_task()
	}
}

#[inline(always)]
pub fn wakeup_task(id: task::TaskId) {
	unsafe {
		let mut sched = SCHEDULER.lock();
		sched.wakeup_task(id)
	}
}

/// Terminate the current running task
#[inline(always)]
pub fn do_exit() {
	unsafe {
		let mut sched = SCHEDULER.lock();
		sched.exit()
	}
}

/// Get the TaskID of the current running task
#[inline(always)]
pub fn get_current_taskid() -> task::TaskId {
	unsafe {
		let sched = SCHEDULER.lock();
		sched.get_current_taskid()
	}
}