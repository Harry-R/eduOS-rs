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
const GICD_BASE: u64 = 0x08000000;
const GICC_BASE: u64 = GICD_BASE + GICD_SIZE;
const GIC_SIZE: u64 = GICD_SIZE + GICC_SIZE;
const GICD_SIZE: u64 = 0x010000;
const GICC_SIZE: u64 = 0x010000;

const GICD_CTLR: u64 = 0x0;
const GICD_TYPER: u64 = 0x4;
const GICD_IIDR: u64 = 0x8;
const GICD_IGROUPR: u64 = 0x80;
const GICD_ISENABLER: u64 = 0x100;
const GICD_ICENABLER: u64 = 0x180;
const GICD_ISPENDR: u64 = 0x200;
const GICD_ICPENDR: u64 = 0x280;
const GICD_ISACTIVER: u64 = 0x300;
const GICD_ICACTIVER: u64 = 0x380;
const GICD_IPRIORITYR: u64 = 0x400;
const GICD_ITARGETSR: u64 = 0x800;
const GICD_ICFGR: u64 = 0xc00;
const GICD_NSACR: u64 = 0xe00;
const GICD_SGIR: u64 = 0xF00;

const GICD_CTLR_ENABLEGRP0: u32 = (1 << 0);
const GICD_CTLR_ENABLEGRP1: u32 = (1 << 1);

/* Physical CPU Interface registers */
const GICC_CTLR: u64 = 0x0;
const GICC_PMR: u64 = 0x4;
const GICC_BPR: u32 = 0x8;
const GICC_IAR: u32 = 0xC;
const GICC_EOIR: u32 = 0x10;
const GICC_RPR: u32 = 0x14;
const GICC_HPPIR: u32 = 0x18;
const GICC_AHPPIR: u32 = 0x28;
const GICC_IIDR: u32 = 0xFC;
const GICC_DIR: u32 = 0x1000;
const GICC_PRIODROP: u32 = GICC_EOIR;

const GICC_CTLR_ENABLEGRP0: u32 = (1 << 0);
const GICC_CTLR_ENABLEGRP1: u32 = (1 << 1);
const GICC_CTLR_FIQEN: u32 = (1 << 3);
const GICC_CTLR_ACKCTL: u32 = (1 << 2);

const MAX_HANDLERS: u32 = 256;
const RESCHED_INT: u32 = 1;

// TODO: find out, what "EINVAL" is
const EINVAL: u32 = 42;

// This is dummy, has to be code pointer array -> Ignore first, maybe implement later,
// if wee need more than one handler
const irq_routines: [i32; MAX_HANDLERS as usize] = [0; MAX_HANDLERS as usize];

/// deceleration for assembly function, that initiates task switch
extern "C" {
	fn _reschedule();
}

/// triggers a reschedule, either by interrupt or by directly calling the scheduler
pub fn trigger_schedule() {
	// by interrupt
	// gicd_write(GICD_SGIR, (2 << 24) | RESCHED_INT);
	// by calling scheduler directly
	unsafe { _reschedule(); }
}

fn gicd_read(off: u64) -> u32 {
	let value;
	unsafe { asm!("ldar w0, [x1]" : "=r"(value) : "{x1}"(GICD_BASE +off as u64) : "memory")};
	return value;
}

fn gicd_write(off: u64, value: u32) -> () {
	unsafe { asm!("str w0, [x1]" : : "rZ" (value), "{x1}" (GICD_BASE +off as u64) : "memory")};
}

fn gicc_read(off: u64) -> u32 {
	let value;
	unsafe{asm!("ldar w0, [x1]" : "=r"(value) : "{x1}"(GICC_BASE +off as u64) : "memory")};
	return value;
}

fn gicc_write(off: u64, value: u32) {
	unsafe{asm!("str w0, [x1]" : : "rZ" (value), "{x1}" (GICC_BASE +off as u64) : "memory")};
}


fn unmask_interrupt(vector: u32) -> Result<(),()>{
    if vector >= (((gicd_read(GICD_TYPER as u64) & 0x1f) + 1) * 32) {
		return Err(());
	}
	// TODO: Implement with spin crate
    // spinlock_irqsave_lock(&mask_lock);
    gic_set_enable(vector as u64, true);
    // spinlock_irqsave_unlock(&mask_lock);
   Ok(())
}

fn mask_interrupt(vector: u32) -> Result<(),()> {
    if vector >= (((gicd_read(GICD_TYPER as u64) & 0x1f) + 1) * 32) {
		return Err(());
	}
	// TODO: Implement with spin crate
    // spinlock_irqsave_lock(&mask_lock);
    gic_set_enable(vector as u64, false);
    // spinlock_irqsave_unlock(&mask_lock);
    Ok(())
}


fn gic_set_enable(vector: u64, enable: bool) {
	if enable == true {
		let regoff = GICD_ISENABLER + 4 * (vector / 32);
		gicd_write(regoff, gicd_read(regoff) | 1 << (vector % 32));
	} else {
		let regoff = GICD_ICENABLER + 4 * (vector / 32);
		gicd_write(regoff, gicd_read(regoff) | 1 << (vector % 32));
	}
}

/// Enable Interrupts
#[no_mangle]
pub fn irq_enable() {
    // Global enable signalling of interrupt from the cpu interface
	gicc_write(GICC_CTLR as u64, (GICC_CTLR_ENABLEGRP0 | GICC_CTLR_ENABLEGRP1 | GICC_CTLR_FIQEN | GICC_CTLR_ACKCTL) as u32);
}

fn gicd_enable() {
	println!("global enable forwarding from gicd");
	// Global enable forwarding interrupts from distributor to cpu interface
	gicd_write(GICD_CTLR, (GICD_CTLR_ENABLEGRP0 | GICD_CTLR_ENABLEGRP1) as u32);
}

fn gicd_disable() {
	// Global disable forwarding interrupts from distributor to cpu interface
	gicd_write(GICD_CTLR, 0);
}

fn gicc_enable() {
	println!("global enable forwarding from gicc");
	// Global enable signalling of interrupt from the cpu interface
    gicc_write(GICC_CTLR, GICC_CTLR_ENABLEGRP0 | GICC_CTLR_ENABLEGRP1 | GICC_CTLR_FIQEN | GICC_CTLR_ACKCTL);
}

fn gicc_disable() {
	// Global disable signalling of interrupt from the cpu interface
	gicc_write(GICC_CTLR, 0);
}

/// Disable Interrupts
pub fn irq_disable() {
	// Global disable signalling of interrupt from the cpu interface
	gicc_write(GICC_CTLR as u64, 0);
}

fn gicc_set_priority(priority: u32) {
	gicc_write(GICC_PMR, priority & 0xFF);
}

pub fn init() {

	println!("initialize interrupt controller");
	gicd_enable();
	gicc_set_priority(0xF0);
	gicc_enable();

	let _ = unmask_interrupt(RESCHED_INT);

    // enable interrupts, clear A, I, F flags
    unsafe { asm!("msr daifclr, 0b111" ::: "memory") };
}

#[no_mangle]
/// Called at unhandled exception
pub fn do_bad_mode(sp: usize, reason: i32){

	println!("Receive unhandled exception - sp: 0x{:x} - reason:{}", sp, reason);

	loop {
		// HALT;
	}
}

#[no_mangle]
pub fn do_sync() -> usize {
	println!("do_sync");
	let iar = gicc_read( GICC_IAR as u64);
	let ret = call_scheduler();
	gicc_write(GICC_EOIR as u64, iar);
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
	gicc_write(GICC_EOIR as u64, iar);
	return ret;
}

#[no_mangle]
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

	gicc_write(GICC_EOIR as u64, iar);

	return ret;
}

#[no_mangle]
pub fn do_error() {
	loop{}
}

#[no_mangle]
fn call_scheduler() -> usize {
	reschedule()
}