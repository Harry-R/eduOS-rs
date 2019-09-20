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
use scheduler::*;

// TODO enhancement: use aarch64 or cortex-a crate for register stuff

/* GIC related constants */
const GICR_BASE: uint = 0;

/* GIC Distributor interface register offsets that are common to GICv3 & GICv2 */
const GICD_CTLR: uint = 0x0;
const GICD_TYPER: uint = 0x4;
const GICD_IIDR: uint = 0x8;
const GICD_IGROUPR: uint = 0x80;
const GICD_ISENABLER: uint = 0x100;
const GICD_ICENABLER: uint = 0x180;
const GICD_ISPENDR: uint = 0x200;
const GICD_ICPENDR: uint = 0x280;
const GICD_ISACTIVER: uint = 0x300;
const GICD_ICACTIVER: uint = 0x380;
const GICD_IPRIORITYR: uint = 0x400;
const GICD_ITARGETSR: uint = 0x800;
const GICD_ICFGR: uint = 0xc00;
const GICD_NSACR: uint = 0xe00;
const GICD_SGIR: uint = 0xF00;

const GICD_CTLR_ENABLEGRP0: uint = (1 << 0);
const GICD_CTLR_ENABLEGRP1: uint = (1 << 1);

/* Physical CPU Interface registers */
const GICC_CTLR: uint = 0x0;
const GICC_PMR: uint = 0x4;
const GICC_BPR: uint = 0x8;
const GICC_IAR: uint = 0xC;
const GICC_EOIR: uint = 0x10;
const GICC_RPR: uint = 0x14;
const GICC_HPPIR: uint = 0x18;
const GICC_AHPPIR: uint = 0x28;
const GICC_IIDR: uint = 0xFC;
const GICC_DIR: uint = 0x1000;
const GICC_PRIODROP: uint = GICC_EOIR;

const GICC_CTLR_ENABLEGRP0: uint = (1 << 0);
const GICC_CTLR_ENABLEGRP1: uint = (1 << 1);
const GICC_CTLR_FIQEN: uint = (1 << 3);
const GICC_CTLR_ACKCTL: uint = (1 << 2);

const MAX_HANDLERS: uint = 256;
const RESCHED_INT: uint = 1;

/// Maximum possible number of interrupts


fn gicd_read(uint64: off) -> uint32 {
	uint32: value;
	unsafe { asm!(volatile("ldar %w0, [%1]" : "=r"(value) : "r"(gicd_base + off) : "memory"))};
	return value;
}

fn gicd_write(uint64: off, uint32: value) -> () {
	unsafe { asm!(volatile("str %w0, [%1]" : : "rZ" (value), "r" (gicd_base + off) : "memory"))};
}

fn gicc_read(uint64: off) -> uint32 {
	uint32: value;
	unsafe{asm!(volatile("ldar %w0, [%1]" : "=r"(value) : "r"(gicc_base + off) : "memory"))};
	return value;
}

fn gicc_write(uint64: off, uint32: value) {
	unsafe{asm!(volatile("str %w0, [%1]" : : "rZ" (value), "r" (gicc_base + off) : "memory"))};
}

/// Enable Interrupts
pub fn irq_enable() {
    // Global enable signalling of interrupt from the cpu interface
	gicc_write(GICC_CTLR, GICC_CTLR_ENABLEGRP0 | GICC_CTLR_ENABLEGRP1 | GICC_CTLR_FIQEN | GICC_CTLR_ACKCTL);
}

/// Disable Interrupts
pub fn irq_disable() {
	// Global disable signalling of interrupt from the cpu interface
	gicc_write(GICC_CTLR, 0);
}


/// Called at unhandled exception
fn do_bad_mode(int: reason){
	LOG_ERROR("Receive unhandled exception: %d\n", reason);

	loop {
		HALT;
	}
}


// TODO: fix return type -> See eduOS-rs
fn do_irq() -> size_t** {
	size_t** ret = NULL;
	uint32: iar = gicc_read(GICC_IAR);
	uint32: vector = iar & 0x3ff;

    // TODO: Implement logging, see HermitCore
	LOG_INFO("Receive interrupt %d\n", vector);

	// Check if timers have expired that would unblock tasks
	check_workqueues_in_irqhandler(vector);

    // TODO: implement according scheduler functions / check, how this is implemented in eduos
	if (get_highest_priority() > per_core(current_task)->prio) {
		// there's a ready task with higher priority
		ret = scheduler();
	}
	gicc_write(GICC_EOIR, iar);
	return ret;
}

// TODO: fix param & return type -> See eduOS-rs
fn do_fiq(void *regs) -> size_t**{
	size_t** ret = NULL;
	uint32_t iar = gicc_read(GICC_IAR);
	uint32_t vector = iar & 0x3ff;

	//LOG_INFO("Receive fiq %d\n", vector);

	if (vector < MAX_HANDLERS && irq_routines[vector]) {
		(irq_routines[vector])(regs);
	} else if (vector != RESCHED_INT) {
		LOG_INFO("Unable to handle fiq %d\n", vector);
	}

	// Check if timers have expired that would unblock tasks
    // TODO: implement this func / check in eduOS / HermitCore
	check_workqueues_in_irqhandler(vector);

	if ((vector == INT_PPI_NSPHYS_TIMER) || (vector == RESCHED_INT)) {
		// a timer interrupt may have caused unblocking of tasks
		ret = scheduler();
	} else if (get_highest_priority() > per_core(current_task)->prio) {
		// there's a ready task with higher priority
		ret = scheduler();
	}

	gicc_write(GICC_EOIR, iar);

	return ret;
}