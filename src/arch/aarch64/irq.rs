// Copyright (c) 2017-2018 Stefan Lankes, RWTH Aachen University
// Copyright (c) 2019 Leonard Rapp, RWTH Aachen University
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![allow(dead_code)]

use core::fmt;
use logging::*;
use scheduler::reschedule;

// TODO enhancement: use aarch64 or cortex-a crate for register stuff

/* GIC related constants */
const GICR_BASE: u64 = 0;

/* GIC Distributor interface register offsets that are common to GICv3 & GICv2 */
const GICD_BASE: i64 = 0x08000000;
const GICC_BASE: i64 = GICD_BASE + GICD_SIZE;
const GIC_SIZE: i64 = GICD_SIZE + GICC_SIZE;
const GICD_SIZE: i64 = 0x010000;
const GICC_SIZE: i64 = 0x010000;

const GICD_CTLR: i32 = 0x0;
const GICD_TYPER: i32 = 0x4;
const GICD_IIDR: i32 = 0x8;
const GICD_IGROUPR: i32 = 0x80;
const GICD_ISENABLER: i32 = 0x100;
const GICD_ICENABLER: i32 = 0x180;
const GICD_ISPENDR: i32 = 0x200;
const GICD_ICPENDR: i32 = 0x280;
const GICD_ISACTIVER: i32 = 0x300;
const GICD_ICACTIVER: i32 = 0x380;
const GICD_IPRIORITYR: i32 = 0x400;
const GICD_ITARGETSR: i32 = 0x800;
const GICD_ICFGR: i32 = 0xc00;
const GICD_NSACR: i32 = 0xe00;
const GICD_SGIR: i32 = 0xF00;

const GICD_CTLR_ENABLEGRP0: i32 = (1 << 0);
const GICD_CTLR_ENABLEGRP1: i32 = (1 << 1);

/* Physical CPU Interface registers */
const GICC_CTLR: i32 = 0x0;
const GICC_PMR: i32 = 0x4;
const GICC_BPR: i32 = 0x8;
const GICC_IAR: i32 = 0xC;
const GICC_EOIR: i32 = 0x10;
const GICC_RPR: i32 = 0x14;
const GICC_HPPIR: i32 = 0x18;
const GICC_AHPPIR: i32 = 0x28;
const GICC_IIDR: i32 = 0xFC;
const GICC_DIR: i32 = 0x1000;
const GICC_PRIODROP: i32 = GICC_EOIR;

const GICC_CTLR_ENABLEGRP0: i32 = (1 << 0);
const GICC_CTLR_ENABLEGRP1: i32 = (1 << 1);
const GICC_CTLR_FIQEN: i32 = (1 << 3);
const GICC_CTLR_ACKCTL: i32 = (1 << 2);

const MAX_HANDLERS: i32 = 256;
const RESCHED_INT: i32 = 1;

// TODO: find out, what "EINVAL" is
const EINVAL: i32 = 42;

// This is dummy, has to be code pointer array -> Ignore first, maybe implement later,
// if wee need more than one handler
const irq_routines: [i32; MAX_HANDLERS as usize] = [0; MAX_HANDLERS as usize];


fn gicd_read(off: u64) -> u32 {
	let value;
	unsafe { asm!("ldar w0, [x1]" : "=r"(value) : "{x1}"(GICD_BASE +off as i64) : "memory")};
	return value;
}

fn gicd_write(off: u64, value: i32) -> () {
	unsafe { asm!("str w0, [x1]" : : "rZ" (value), "{x1}" (GICD_BASE +off as i64) : "memory")};
}

fn gicc_read(off: u64) -> u32 {
	let value;
	unsafe{asm!("ldar w0, [x1]" : "=r"(value) : "{x1}"(GICC_BASE +off as i64) : "memory")};
	return value;
}

fn gicc_write(off: u64, value: i32) {
	unsafe{asm!("str w0, [x1]" : : "rZ" (value), "{x1}" (GICC_BASE +off as i64) : "memory")};
}


fn unmask_interrupt(vector: u32) -> i32{
    if vector >= (((gicd_read(GICD_TYPER as u64) & 0x1f) + 1) * 32) {
		return -EINVAL;
	}
	// TODO: Implement with spin crate
    // spinlock_irqsave_lock(&mask_lock);
    gic_set_enable(vector, true);
    // spinlock_irqsave_unlock(&mask_lock);

    return 0;
}

fn mask_interrupt(vector: u32) -> i32 {
    if vector >= (((gicd_read(GICD_TYPER as u64) & 0x1f) + 1) * 32) {
		return -EINVAL;
	}
	// TODO: Implement with spin crate
    // spinlock_irqsave_lock(&mask_lock);
    gic_set_enable(vector, false);
    // spinlock_irqsave_unlock(&mask_lock);

    return 0;
}


fn gic_set_enable(vector: u32, enable: bool) {
    if enable {
        let regoff: u64 = (GICD_ISENABLER + (4 * (vector / 32) as i32)) as u64;
        gicd_write(regoff, (gicd_read(regoff) | (1 << (vector % 32))) as i32);
    } else {
        let regoff :u64 = (GICD_ICENABLER + (4 * (vector / 32) as i32)) as u64;;
        gicd_write(regoff, (gicd_read(regoff) | (1 << (vector % 32))) as i32);
    }
}

/// Enable Interrupts
#[no_mangle]
pub fn irq_enable() {
    // Global enable signalling of interrupt from the cpu interface
	gicc_write(GICC_CTLR as u64, GICC_CTLR_ENABLEGRP0 | GICC_CTLR_ENABLEGRP1 | GICC_CTLR_FIQEN | GICC_CTLR_ACKCTL);
}

/// Disable Interrupts
pub fn irq_disable() {
	// Global disable signalling of interrupt from the cpu interface
	gicc_write(GICC_CTLR as u64, 0);
}

#[no_mangle]
/// Called at unhandled exception
pub fn do_bad_mode(reason: i32){
	// LOG_ERROR("Receive unhandled exception: %d\n", reason);

	loop {
		// HALT;
	}
}

#[no_mangle]
pub fn do_sync() -> usize {
	println!("do_sync");
	let iar = gicc_read( GICC_IAR as u64);
	let ret = call_scheduler();
	gicc_write(GICC_EOIR as u64, iar as i32);
	println!("new sp: 0x{:x}", ret);
	return ret;
}

#[no_mangle]
pub fn do_irq() -> usize {
	println!("do irq");
	let mut ret = 0;
	let iar = gicc_read( GICC_IAR as u64);
	let vector = iar & 0x3ff;

    // TODO: nice to have: Implement logging, see HermitCore
	// LOG_INFO("Receive interrupt %d\n", vector);

	// Check if timers have expired that would unblock tasks
	// Maybe implement later
	// check_workqueues_in_irqhandler(vector);

    // implement later, for now it is enough to call scheduler in every case
	// Look for highest priority task and return it's stack pointer,
	// if (get_highest_priority() > per_core(current_task)->prio) {
		// there's a ready task with higher priority
		ret = call_scheduler();
	// 	}
	gicc_write(GICC_EOIR as u64, iar as i32);
	return ret;
}

fn do_fiq(reg_ptr: u64) -> usize{
	let mut ret = 0;
	let iar = gicc_read(GICC_IAR as u64);
	let vector = iar & 0x3ff;

	//// LOG_INFO("Receive fiq %d\n", vector);

	if vector < MAX_HANDLERS as u32 && irq_routines[vector as usize] != 0 {
		// implement later, if real irq handlers are needed
		// (irq_routines[vector as usize])(regs);
	} else if vector != RESCHED_INT as u32 {
		// LOG_INFO("Unable to handle fiq %d\n", vector);
	}

	// Check if timers have expired that would unblock tasks
    // Ignore first, maybe implement later
	// check_workqueues_in_irqhandler(vector);

	// implement later, for now it is enough to call scheduler in every case
	/*
	if (vector == INT_PPI_NSPHYS_TIMER) || (vector == RESCHED_INT as u32) {
		// a timer interrupt may have caused unblocking of tasks
		ret = scheduler();
	} else if get_highest_priority() > per_core(current_task).prio {
		// there's a ready task with higher priority
	*/
		ret = call_scheduler();
	//}

	gicc_write(GICC_EOIR as u64, iar as i32);

	return ret;
}

#[no_mangle]
pub fn do_error() {
	loop{}
}

/// dummy scheduler fun
// TODO: connect to real scheduler
fn call_scheduler() -> usize {
	reschedule()
}