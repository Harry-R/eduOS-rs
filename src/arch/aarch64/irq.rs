// Copyright (c) 2017-2018 Stefan Lankes, RWTH Aachen University
// Copyright (c) 2019 Leonard Rapp, RWTH Aachen University
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![allow(dead_code)]

use arch::aarch64::task::State;
use arch::aarch64::timer;
use scheduler::reschedule;

// TODO enhancement: use aarch64 or cortex-a crate for register stuff

/* GIC related constants */
const GICR_BASE: u64 = 0x080A0000;

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
const EL1_PHYS_TIMER: u32 = 30;

// TODO: find out, what "EINVAL" is
const EINVAL: i32 = 42;

// This is dummy, has to be code pointer array -> Ignore first, maybe implement later,
// if wee need more than one handler
const IRQ_ROUTINES: [i32; MAX_HANDLERS as usize] = [0; MAX_HANDLERS as usize];

/// deceleration for assembly function, that initiates task switch
extern "C" {
    fn _reschedule();
}

/// Triggers a reschedule, either by interrupt or by directly calling the scheduler
pub fn trigger_schedule() {
    println!("Triggering schedule");
    gicd_write(GICD_SGIR, (2 << 24) | RESCHED_INT);
    // unsafe { _reschedule(); }
    println!("goto trigger loop!");
    loop {}
}

/// Performs a read to a memory mapped GICD register
/// * `off` - The register's offset from GICD_BASE
fn gicd_read(off: u64) -> u32 {
    let value;
    unsafe {
        asm!("ldar w0, [x1]" : "=r"(value) : "{x1}"(GICD_BASE + off as u64) : "memory" : "volatile")
    };
    return value;
}

/// Performs a write to a memory mapped GICD register
/// * `off` - The register's offset from GICD_BASE
/// * `value` - The value to be written
fn gicd_write(off: u64, value: u32) -> () {
    unsafe {
        asm!("str w0, [x1]" : : "rZ" (value), "{x1}" (GICD_BASE + off as u64) : "memory" : "volatile")
    };
}

/// Performs a write to a memory mapped GICC register
/// * `off` - The register's offset from GICC_BASE
fn gicc_read(off: u64) -> u32 {
    let value;
    unsafe {
        asm!("ldar w0, [x1]" : "=r"(value) : "{x1}"(GICC_BASE + off as u64) : "memory" : "volatile")
    };
    return value;
}

/// Performs a write to a memory mapped GICC register
/// * `off` - The register's offset from GICC_BASE
/// * `value` - The value to be written
fn gicc_write(off: u64, value: u32) {
    unsafe {
        asm!("str w0, [x1]" : : "rZ" (value), "{x1}" (GICC_BASE + off as u64) : "memory" : "volatile")
    };
}

/// Unmasks an interrupt with a specific id
/// * `vector` - The interrupt id (INTID)
fn unmask_interrupt(vector: u32) -> Result<(), ()> {
    if vector >= (((gicd_read(GICD_TYPER as u64) & 0x1f) + 1) * 32) {
        return Err(());
    }
    // TODO: Implement with spin crate
    // spinlock_irqsave_lock(&mask_lock);
    gic_set_enable(vector as u64, true);
    // spinlock_irqsave_unlock(&mask_lock);
    Ok(())
}

/// Unmasks an interrupt with a specific id
/// * `vector` - The interrupt id (INTID)
fn mask_interrupt(vector: u32) -> Result<(), ()> {
    if vector >= (((gicd_read(GICD_TYPER as u64) & 0x1f) + 1) * 32) {
        return Err(());
    }
    // TODO: Implement with spin crate
    // spinlock_irqsave_lock(&mask_lock);
    gic_set_enable(vector as u64, false);
    // spinlock_irqsave_unlock(&mask_lock);
    Ok(())
}

/// Enable / disable interrupts in redistributor according to ARM IHI 0069C, chapter 8.9.15
/// * `vector` - The interrupt id (INTID)
/// * `enable` - True for enable, false for disable
fn gic_set_enable(vector: u64, enable: bool) {
    if enable == true {
        let regoff = GICD_ISENABLER + 4 * (vector / 32);
        let val = gicd_read(regoff) | 1 << (vector % 32);
        gicd_write(regoff, val);
    } else {
        let regoff = GICD_ICENABLER + 4 * (vector / 32);
        gicd_write(regoff, gicd_read(regoff) | 1 << (vector % 32));
    }
}

/// Enable Interrupts at GICC level
#[no_mangle]
pub fn irq_enable() {
    // Global enable signalling of interrupt from the cpu interface
    gicc_write(
        GICC_CTLR as u64,
        (GICC_CTLR_ENABLEGRP0 | GICC_CTLR_ENABLEGRP1 | GICC_CTLR_FIQEN | GICC_CTLR_ACKCTL) as u32,
    );
}

/// Enable interrupts at GICD level
fn gicd_enable() {
    println!("global enable forwarding from gicd");
    // Global enable forwarding interrupts from distributor to cpu interface
    gicd_write(
        GICD_CTLR,
        (GICD_CTLR_ENABLEGRP0 | GICD_CTLR_ENABLEGRP1) as u32,
    );
}

/// Disable interrupts at GICD level
fn gicd_disable() {
    // Global disable forwarding interrupts from distributor to cpu interface
    gicd_write(GICD_CTLR, 0);
}

/// Enable Interrupts at GICC level
fn gicc_enable() {
    println!("global enable forwarding from gicc");
    // Global enable signalling of interrupt from the cpu interface
    gicc_write(
        GICC_CTLR,
        GICC_CTLR_ENABLEGRP0 | GICC_CTLR_ENABLEGRP1 | GICC_CTLR_FIQEN | GICC_CTLR_ACKCTL,
    );
}

/// Disable interrupts at GICC level
fn gicc_disable() {
    // Global disable signalling of interrupt from the cpu interface
    gicc_write(GICC_CTLR, 0);
}

/// Disable Interrupts at GICC level
pub fn irq_disable() {
    // Global disable signalling of interrupt from the cpu interface
    gicc_write(GICC_CTLR as u64, 0);
}

/// Set priority at GICC
/// * `priority` - The priority to set (0-255)
fn gicc_set_priority(priority: u32) {
    gicc_write(GICC_PMR, priority & 0xFF);
}

/// Initialize the GIC:
/// - call all necessary init functions
/// - Print some information
/// - unmask `RESCHED_INT`
#[no_mangle]
pub fn gic_irq_init() {
    println!("initialize interrupt controller");

    let mut current_el: u64;
    unsafe {
        asm!("mrs $0, CurrentEL" : "=r" (current_el) :: "memory" : "volatile");
    }
    println!("Running in exception level {}", current_el >> 2);

    gicc_disable();
    gicd_disable();

    let nr_irqs = ((gicd_read(GICD_TYPER) & 0x1f) + 1) * 32;
    println!("Number of supported interrupts {}", nr_irqs);

    irq_enable();
    gicd_enable();
    gicc_set_priority(0xF0);
    gicc_enable();

    let _ = unmask_interrupt(RESCHED_INT);

    // enable interrupts, clear A, I, F flags
    unsafe { asm!("msr daifclr, 0b111" ::: "memory") };

    println!("GIC initialized!");
}

/// Dis / enable interrupts generated by EL1 physical timers
/// * `unmask`: bool to decide, if en- or disable
pub fn unmask_cntp_el0(unmask: bool) {
    if unmask {
        let _ = unmask_interrupt(EL1_PHYS_TIMER);
    } else {
        let _ = mask_interrupt(EL1_PHYS_TIMER);
    }
}

#[no_mangle]
/// Called at unhandled exception, print error message, goto loop
pub fn do_bad_mode(sp: usize, reason: i32) {
    println!(
        "Receive unhandled exception - sp: 0x{:x} - reason:{}",
        sp, reason
    );

    loop {
        // HALT;
    }
}

/// Handler for synchronous interrupts (exceptions)
/// * `state` - current process state
///
/// - read iar, esr and elr and print according information
/// - write to end of interrupt register
/// - call `do_error()` function
#[no_mangle]
pub fn do_sync(state: *const State) {
    println!("Receive synchronous interrupt");
    unsafe {
        println!("{:?}", *state);
    }
    let iar = gicc_read(GICC_IAR as u64);
    let esr = read_esr();
    println!("Exception Syndrome Register 0x{:x}", esr);
    gicc_write(GICC_EOIR as u64, iar);
    println!("error at 0x{:x}", read_elr());
    do_error(state);
}

/// Read exception link register (elr), return it's value
fn read_elr() -> u64 {
    let mut ret: u64;
    unsafe {
        asm!("mrs $0, elr_el1" : "=r"(ret) :: "memory" : "volatile");
    }
    ret
}

/// Read exception syndrome register (esr), return it's value
fn read_esr() -> u64 {
    let mut val: u64;
    unsafe {
        asm!("mrs $0, esr_el1" : "=r"(val) :: "memory" : "volatile");
    }
    return val;
}

/// Handler for IRQ
/// * `_state` - The current process state
///
/// - read iar
/// - check for interrupt type
/// - call according handler (only scheduler implemented yet)
/// - write to end of interrupt register (eoir)
#[no_mangle]
pub fn do_irq(_state: *const State) -> usize {
    let iar = gicc_read(GICC_IAR as u64);
    let vector = iar & 0x3ff;

    println!("Receive irq {}", vector);
    // unsafe { println!("{:?}", *state); }

    let ret = if true /*vector == RESCHED_INT*/ {
        call_scheduler()
    } else {
        0
    };

    gicc_write(GICC_EOIR as u64, iar);

    ret
}

/// Handler for FIQ
/// * `_state` - The current process state
///
/// - read iar
/// - check for interrupt type
/// - call according handler (only scheduler implemented yet)
/// - write to end of interrupt register (eoir)
#[no_mangle]
fn do_fiq(_state: *const State) -> usize {
    let iar = gicc_read(GICC_IAR as u64);
    let vector = iar & 0x3ff;
    println!("Receive fiq {}", vector);
    // unsafe { println!("{:?}", *state); }

    let ret = if true
    /* vector == RESCHED_INT */
    {
        timer::set_tval(123456);
        call_scheduler()
    } else {
        0
    };

    gicc_write(GICC_EOIR as u64, iar);
    println!("fiq ret");
    ret
}

/// Error function, called at unhandled error
/// *  `state` - The current process state
///
/// - Print error message
/// - goto endless loop
#[no_mangle]
pub fn do_error(state: *const State) {
    println!("UNHANDLED ERROR!");
    println!("Current state:");
    println!("{:?}", state);
    loop {}
}

/// interface for calling the `reschedule()` function
#[no_mangle]
pub fn call_scheduler() -> usize {
    reschedule()
}
