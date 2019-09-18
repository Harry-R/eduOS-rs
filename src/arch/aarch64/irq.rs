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
use synch::spinlock::*;
use x86::dtables::{DescriptorTablePointer,lidt};
use x86::Ring;
use x86::bits64::paging::VAddr;
use x86::segmentation::{SegmentSelector,SystemDescriptorTypes64};
use x86::io::*;

// TODO: use aarch64 or cortex-a crate for register stuff

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
const IDT_ENTRIES: usize = 256;
const KERNEL_CODE_SELECTOR: SegmentSelector = SegmentSelector::new(1, Ring::Ring0);


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

/*/// Determines, if the interrupt flags (IF) is set
pub fn is_irq_enabled() -> bool
// TODO: aarch64
{
	let rflags: u64;

	unsafe { asm!("pushf; pop $0": "=r"(rflags) :: "memory" : "volatile") };
	if (rflags & (1u64 << 9)) !=  0 {
		return true;
	}

	false
}*/

/// Disable IRQs (nested)
///
/// Disable IRQs when unsure if IRQs were enabled at all.
/// This function together with irq_nested_enable can be used
/// in situations when interrupts shouldn't be activated if they
/// were not activated before calling this function.
pub fn irq_nested_disable() -> bool {
	let was_enabled = is_irq_enabled();
	irq_disable();
	was_enabled
}

/// Enable IRQs (nested)
///
/// Can be used in conjunction with irq_nested_disable() to only enable
/// interrupts again if they were enabled before.
pub fn irq_nested_enable(was_enabled: bool) {
	if was_enabled == true {
		irq_enable();
	}
}

pub fn gicd_enable() {
	// Global enable forwarding interrupts from distributor to cpu interface
	gicd_write(GICD_CTLR, GICD_CTLR_ENABLEGRP0 | GICD_CTLR_ENABLEGRP1);
}

pub fn gicd_disable() {
	// Global disable forwarding interrupts from distributor to cpu interface
	gicd_write(GICD_CTLR, 0);
}

pub fn gicc_set_priority(uint32: priority) {
	gicc_write(GICC_PMR, priority & 0xFF);
}

pub fn gic_set_enable(uint32: vector, bool: enable) {
	if enable {
		let uint32: regoff = GICD_ISENABLER + 4 * (vector / 32);
		gicd_write(regoff, gicd_read(regoff) | (1 << (vector % 32)));
	} else {
		let uint32: regoff = GICD_ICENABLER + 4 * (vector / 32);
		gicd_write(regoff, gicd_read(regoff) | (1 << (vector % 32)));
	}
}

pub fn unmask_interrupt(uint32: vector) -> int {
	if vector >= nr_irqs {
        return -EINVAL;
    }
	spinlock_irqsave_lock(&mask_lock);
	gic_set_enable(vector, true);
	spinlock_irqsave_unlock(&mask_lock);
	return 0;
}

pub fn mask_interrupt(uint32: vector) -> int {
	if vector >= nr_irqs {
        return -EINVAL;
    }
	spinlock_irqsave_lock(&mask_lock);
	gic_set_enable(vector, false);
	spinlock_irqsave_unlock(&mask_lock);
	return 0;
}

/* This installs a custom IRQ handler for the given IRQ */
pub fn irq_install_handler(uint: irq, irq_handler_t: handler) -> int {
	if irq >= MAX_HANDLERS {
        return -EINVAL;
    }
	irq_routines[irq] = handler;
	unmask_interrupt(irq);
	return 0;
}

/* This clears the handler for a given IRQ */
pub fn  irq_uninstall_handler(uint: irq) -> int {
	if irq >= MAX_HANDLERS {
        return -EINVAL;
    }
	irq_routines[irq] = NULL;
	mask_interrupt(irq);
	return 0;
}

pub fn irq_post_init() -> int {
	let mut ret;

	LOG_INFO("Enable interrupt handling\n");

	ret = vma_add(GICD_BASE, GICD_BASE+GIC_SIZE, VMA_READ|VMA_WRITE);
	if (BUILTIN_EXPECT(ret, 0)) {
        LOG_ERROR("Failed to intialize interrupt controller\n");
        return ret
    }
	ret = page_map(gicd_base, GICD_BASE, GIC_SIZE >> PAGE_BITS, PG_GLOBAL|PG_RW|PG_DEVICE);
    if BUILTIN_EXPECT(ret, 0) {
        LOG_ERROR("Failed to intialize interrupt controller\n");
        return ret
    }
	LOG_INFO("Map gicd 0x%zx at 0x%zx\n", GICD_BASE, gicd_base);
	LOG_INFO("Map gicc 0x%zx at 0x%zx\n", GICC_BASE, gicc_base);

	gicc_disable();
	gicd_disable();

	nr_irqs = ((gicd_read(GICD_TYPER) & 0x1f) + 1) * 32;
	LOG_INFO("Number of supported interrupts %u\n", nr_irqs);

	gicd_write(GICD_ICENABLER, 0xffff0000);
	gicd_write(GICD_ISENABLER, 0x0000ffff);
	gicd_write(GICD_ICPENDR, 0xffffffff);
	gicd_write(GICD_IGROUPR, 0);

	for i in 0..32/4 {
		gicd_write(GICD_IPRIORITYR + i * 4, 0x80808080);
	}

	for i in  32/16..nr_irqs/16 {
		gicd_write(GICD_NSACR + i * 4, 0xffffffff);
	}

	for i in 32/32..nr_irqs/32 {
		gicd_write(GICD_ICENABLER + i * 4, 0xffffffff);
		gicd_write(GICD_ICPENDR + i * 4, 0xffffffff);
		gicd_write(GICD_IGROUPR + i * 4, 0);
	}

	for i  in 32/4..nr_irqs/4 {
		gicd_write(GICD_ITARGETSR + i * 4, 0);
		gicd_write(GICD_IPRIORITYR + i * 4, 0x80808080);
	}

	gicd_enable();

	gicc_set_priority(0xF0);
	gicc_enable();

	unmask_interrupt(RESCHED_INT);

	return 0;
}

pub fn do_sync(void: *regs) {
	uint32: iar = gicc_read(GICC_IAR);
	uint32: esr = read_esr();
	uint32: ec = esr >> 26;
	uint32: iss = esr & 0xFFFFFF;
	uint64: pc = get_elr();

    /* data abort from lower or current level */
	if ec == 0b100100 || (ec == 0b100101) {
		/* check if value in far_el1 is valid */
		if !(iss & (1 << 10)) {
			/* read far_el1 register, which holds the faulting virtual address */
			uint64: far = read_far();

			if page_fault_handler(far, pc) == 0 {
                return;
            }
			LOG_ERROR("Unable to handle page fault at 0x%llx\n", far);
			LOG_ERROR("Exception return address 0x%llx\n", get_elr());
			LOG_ERROR("Thread ID register 0x%llx\n", get_tpidr());
			LOG_ERROR("Table Base Register 0x%llx\n", get_ttbr0());
			LOG_ERROR("Exception Syndrome Register 0x%lx\n", esr);

			// send EOI
			gicc_write(GICC_EOIR, iar);
			//do_abort();
			sys_exit(-EFAULT);
		} else {
			LOG_ERROR("Unknown exception\n");
		}
	} else if ec == 0x3c {
		LOG_ERROR("Trap to debugger, PC=0x%x\n", pc);
	} else {
		LOG_ERROR("Unsupported exception class: 0x%x, PC=0x%x\n", ec, pc);
	}

	sys_exit(-EFAULT);

}

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

fn do_irq() -> size_t** {
	size_t** ret = NULL;
	uint32: iar = gicc_read(GICC_IAR);
	uint32: vector = iar & 0x3ff;

	LOG_INFO("Receive interrupt %d\n", vector);

	// Check if timers have expired that would unblock tasks
	check_workqueues_in_irqhandler(vector);

	if (get_highest_priority() > per_core(current_task)->prio) {
		// there's a ready task with higher priority
		ret = scheduler();
	}
	gicc_write(GICC_EOIR, iar);
	return ret;
}

fn do_error() {
	LOG_ERROR("Receive error interrupt\n");

	loop {
		HALT;
	}
}

fn do_bad_mode(int: reason){
	LOG_ERROR("Receive unhandled exception: %d\n", reason);

	loop {
		HALT;
	}
}

fn reschedule(){
	// (2 << 24) = Forward the interrupt only to the CPU interface of the PE that requested the interrupt
	gicd_write(GICD_SGIR, (2 << 24) | RESCHED_INT);
}


////////////


fn get_daif() -> uint32 {
	size_t: flags;
	asm volatile("mrs %0, daif" : "=r"(flags) :: "memory");
	return flags;
}

/** @brief Determines, if the exception bit mask bits (DAIF) allows exceptions
 *
 * @return
 * - 1 DAIF is cleared and allows exceptions
 * - 0 DAIF is cleared and allows exceptions
 */
inline static uint8_t is_irq_enabled(void)
{
	size_t flags = get_daif();
	if (flags & (IRQ_FLAG_A|IRQ_FLAG_I|IRQ_FLAG_F))
		return 0;
	return 1;
}

/** @brief Disable IRQs
 *
 * This inline function just set the exception bit mask bits
 */
 static inline void irq_disable(void) {
         asm volatile("msr daifset, 0b111" ::: "memory");
 }

/** @brief Enable IRQs
 *
 * This inline function just clear out the exception bit mask bits
 */
static inline void irq_enable(void) {
        asm volatile("msr daifclr, 0b111" ::: "memory");
}

/** @brief Disable IRQs (nested)
 *
 * Disable IRQs when unsure if IRQs were enabled at all.
 * This function together with irq_nested_enable can be used
 * in situations when interrupts shouldn't be activated if they
 * were not activated before calling this function.
 *
 * @return Whether IRQs had been enabled or not before disabling
 */
inline static uint8_t irq_nested_disable(void) {
	uint8_t was_enabled = is_irq_enabled();
	irq_disable();
	return was_enabled;
}

/** @brief Enable IRQs (nested)
 *
 * Can be used in conjunction with irq_nested_disable() to only enable
 * interrupts again if they were enabled before.
 *
 * @param was_enabled Whether IRQs should be enabled or not
 */
inline static void irq_nested_enable(uint8_t was_enabled) {
	if (was_enabled)
		irq_enable();
}






/*







#[inline(always)]
fn send_eoi_to_slave()
{
	/*
	 * If the IDT entry that was invoked was greater-than-or-equal to 40
	 * and lower than 48 (meaning IRQ8 - 15), then we need to
	 * send an EOI to the slave controller of the PIC
	 */
	unsafe { outb(0xA0, 0x20); }
}

#[inline(always)]
fn send_eoi_to_master()
{
	/*
	 * In either case, we need to send an EOI to the master
	 * interrupt controller of the PIC, too
	 */
	unsafe { outb(0x20, 0x20); }
}


/// An interrupt gate descriptor.
///
/// See Intel manual 3a for details, specifically section "6.14.1 64-Bit Mode
/// IDT" and "Figure 6-7. 64-Bit IDT Gate Descriptors".
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
struct IdtEntry {
    /// Lower 16 bits of ISR.
    pub base_lo: u16,
    /// Segment selector.
    pub selector: SegmentSelector,
    /// This must always be zero.
    pub ist_index: u8,
    /// Flags.
    pub flags: u8,
    /// The upper 48 bits of ISR (the last 16 bits must be zero).
    pub base_hi: u64,
    /// Must be zero.
    pub reserved1: u16,
}

enum Type {
    InterruptGate,
    TrapGate
}

impl Type {
    pub fn pack(self) -> u8 {
        match self {
            Type::InterruptGate => SystemDescriptorTypes64::InterruptGate as u8,
			Type::TrapGate => SystemDescriptorTypes64::TrapGate as u8
        }
    }
}

impl IdtEntry {
    /// A "missing" IdtEntry.
    ///
    /// If the CPU tries to invoke a missing interrupt, it will instead
    /// send a General Protection fault (13), with the interrupt number and
    /// some other data stored in the error code.
    pub const MISSING: IdtEntry = IdtEntry {
        base_lo: 0,
        selector: SegmentSelector::from_raw(0),
        ist_index: 0,
        flags: 0,
        base_hi: 0,
        reserved1: 0,
    };

    /// Create a new IdtEntry pointing at `handler`, which must be a function
    /// with interrupt calling conventions.  (This must be currently defined in
    /// assembly language.)  The `gdt_code_selector` value must be the offset of
    /// code segment entry in the GDT.
    ///
    /// The "Present" flag set, which is the most common case.  If you need
    /// something else, you can construct it manually.
    pub fn new(handler: VAddr, gdt_code_selector: SegmentSelector,
               dpl: Ring, ty: Type, ist_index: u8) -> IdtEntry {
        assert!(ist_index < 0b1000);
        IdtEntry {
            base_lo: ((handler.as_usize() as u64) & 0xFFFF) as u16,
            base_hi: handler.as_usize() as u64 >> 16,
            selector: gdt_code_selector,
            ist_index: ist_index,
            flags: dpl as u8
                |  ty.pack()
                |  (1 << 7),
            reserved1: 0,
        }
    }
}


static INTERRUPT_HANDLER: SpinlockIrqSave<InteruptHandler> = SpinlockIrqSave::new(InteruptHandler::new());

struct InteruptHandler {
	/// An Interrupt Descriptor Table which specifies how to respond to each
	/// interrupt.
	idt: [IdtEntry; IDT_ENTRIES]
}

impl InteruptHandler {
	pub const fn new() -> InteruptHandler {
		InteruptHandler {
			idt: [IdtEntry::MISSING; IDT_ENTRIES]
		}
	}

	pub fn add_handler(&mut self, int_no: usize,
		func: extern "x86-interrupt" fn (&mut ExceptionStackFrame))
	{
		if int_no < IDT_ENTRIES {
			self.idt[int_no] = IdtEntry::new(VAddr::from_usize(func as usize),
				KERNEL_CODE_SELECTOR, Ring::Ring0, Type::InterruptGate, 0);
		} else {
			info!("unable to add handler for interrupt {}", int_no);
		}
	}

	pub fn remove_handler(&mut self, int_no: usize)
	{
		if int_no < IDT_ENTRIES {
			if int_no < 40 {
				self.idt[int_no] = IdtEntry::new(VAddr::from_usize(unhandled_irq1 as usize),
					KERNEL_CODE_SELECTOR, Ring::Ring0, Type::InterruptGate, 0);
			} else {
				// send  eoi to the master and to the slave
				self.idt[int_no] = IdtEntry::new(VAddr::from_usize(unhandled_irq2 as usize),
					KERNEL_CODE_SELECTOR, Ring::Ring0, Type::InterruptGate, 0);
			}
		} else {
			info!("unable to remove handler for interrupt {}", int_no);
		}
	}

	pub unsafe fn load_idt(&mut self) {
		self.idt[0] = IdtEntry::new(VAddr::from_usize(divide_by_zero_exception as usize),
			KERNEL_CODE_SELECTOR, Ring::Ring0, Type::InterruptGate, 0);
		self.idt[1] = IdtEntry::new(VAddr::from_usize(debug_exception as usize),
			KERNEL_CODE_SELECTOR, Ring::Ring0, Type::InterruptGate, 0);
		self.idt[2] = IdtEntry::new(VAddr::from_usize(nmi_exception as usize),
			KERNEL_CODE_SELECTOR, Ring::Ring0, Type::InterruptGate, 0);
		self.idt[3] = IdtEntry::new(VAddr::from_usize(int3_exception as usize),
			KERNEL_CODE_SELECTOR, Ring::Ring0, Type::InterruptGate, 0);
		self.idt[4] = IdtEntry::new(VAddr::from_usize(int0_exception as usize),
			KERNEL_CODE_SELECTOR, Ring::Ring0, Type::InterruptGate, 0);
		self.idt[5] = IdtEntry::new(VAddr::from_usize(out_of_bound_exception as usize),
			KERNEL_CODE_SELECTOR, Ring::Ring0, Type::InterruptGate, 0);
		self.idt[6] = IdtEntry::new(VAddr::from_usize(invalid_opcode_exception as usize),
			KERNEL_CODE_SELECTOR, Ring::Ring0, Type::InterruptGate, 0);
		self.idt[7] = IdtEntry::new(VAddr::from_usize(no_coprocessor_exception as usize),
			KERNEL_CODE_SELECTOR, Ring::Ring0, Type::InterruptGate, 0);
		self.idt[8] = IdtEntry::new(VAddr::from_usize(double_fault_exception as usize),
			KERNEL_CODE_SELECTOR, Ring::Ring0, Type::InterruptGate, 0);
		self.idt[9] = IdtEntry::new(VAddr::from_usize(overrun_exception as usize),
			KERNEL_CODE_SELECTOR, Ring::Ring0, Type::InterruptGate, 0);
		self.idt[10] = IdtEntry::new(VAddr::from_usize(bad_tss_exception as usize),
			KERNEL_CODE_SELECTOR, Ring::Ring0, Type::InterruptGate, 0);
		self.idt[11] = IdtEntry::new(VAddr::from_usize(not_present_exception as usize),
			KERNEL_CODE_SELECTOR, Ring::Ring0, Type::InterruptGate, 0);
		self.idt[12] = IdtEntry::new(VAddr::from_usize(stack_fault_exception as usize),
			KERNEL_CODE_SELECTOR, Ring::Ring0, Type::InterruptGate, 0);
		self.idt[13] = IdtEntry::new(VAddr::from_usize(general_protection_exception as usize),
			KERNEL_CODE_SELECTOR, Ring::Ring0, Type::InterruptGate, 0);
		self.idt[14] = IdtEntry::new(VAddr::from_usize(page_fault_exception as usize),
			KERNEL_CODE_SELECTOR, Ring::Ring0, Type::InterruptGate, 0);
		self.idt[15] = IdtEntry::new(VAddr::from_usize(reserved_exception as usize),
			KERNEL_CODE_SELECTOR, Ring::Ring0, Type::InterruptGate, 0);
		self.idt[16] = IdtEntry::new(VAddr::from_usize(floating_point_exception as usize),
			KERNEL_CODE_SELECTOR, Ring::Ring0, Type::InterruptGate, 0);
		self.idt[17] = IdtEntry::new(VAddr::from_usize(alignment_check_exception as usize),
			KERNEL_CODE_SELECTOR, Ring::Ring0, Type::InterruptGate, 0);
		self.idt[18] = IdtEntry::new(VAddr::from_usize(machine_check_exception as usize),
			KERNEL_CODE_SELECTOR, Ring::Ring0, Type::InterruptGate, 0);
		for i in 19..32 {
			self.idt[i] = IdtEntry::new(VAddr::from_usize(reserved_exception as usize),
				KERNEL_CODE_SELECTOR, Ring::Ring0, Type::InterruptGate, 0);
		}
		self.idt[32] = IdtEntry::new(VAddr::from_usize(timer_handler as usize),
			KERNEL_CODE_SELECTOR, Ring::Ring0, Type::InterruptGate, 0);

		// send only eoi to the master
		for i in 33..40 {
			self.idt[i] = IdtEntry::new(VAddr::from_usize(unhandled_irq1 as usize),
				KERNEL_CODE_SELECTOR, Ring::Ring0, Type::InterruptGate, 0);
		}
		// send  eoi to the master and to the slave
		for i in 40..IDT_ENTRIES {
			self.idt[i] = IdtEntry::new(VAddr::from_usize(unhandled_irq2 as usize),
				KERNEL_CODE_SELECTOR, Ring::Ring0, Type::InterruptGate, 0);
		}

		let idtr = DescriptorTablePointer::new(&self.idt);
		lidt(&idtr);
	}
}

/// Normally, IRQs 0 to 7 are mapped to entries 8 to 15. This
/// is a problem in protected mode, because IDT entry 8 is a
/// Double Fault! Without remapping, every time IRQ0 fires,
/// you get a Double Fault Exception, which is NOT what's
/// actually happening. We send commands to the Programmable
/// Interrupt Controller (PICs - also called the 8259's) in
/// order to make IRQ0 to 15 be remapped to IDT entries 32 to
/// 47
unsafe fn irq_remap()
{
	outb(0x20, 0x11);
	outb(0xA0, 0x11);
	outb(0x21, 0x20);
	outb(0xA1, 0x28);
	outb(0x21, 0x04);
	outb(0xA1, 0x02);
	outb(0x21, 0x01);
	outb(0xA1, 0x01);
	outb(0x21, 0x00);
	outb(0xA1, 0x00);
}

pub fn init() {
	debug!("initialize interrupt descriptor table");

	unsafe {
		irq_remap();

		// load address of the IDT
		INTERRUPT_HANDLER.lock().load_idt();
	}
}

// derived from hilipp Oppermann's blog
// => https://github.com/phil-opp/blog_os/blob/master/src/interrupts/mod.rs

/// Represents the exception stack frame pushed by the CPU on exception entry.
#[repr(C)]
pub struct ExceptionStackFrame {
    /// This value points to the instruction that should be executed when the interrupt
    /// handler returns. For most interrupts, this value points to the instruction immediately
    /// following the last executed instruction. However, for some exceptions (e.g., page faults),
    /// this value points to the faulting instruction, so that the instruction is restarted on
    /// return. See the documentation of the `Idt` fields for more details.
    pub instruction_pointer: u64,
    /// The code segment selector, padded with zeros.
    pub code_segment: u64,
    /// The flags register before the interrupt handler was invoked.
    pub cpu_flags: u64,
    /// The stack pointer at the time of the interrupt.
    pub stack_pointer: u64,
    /// The stack segment descriptor at the time of the interrupt (often zero in 64-bit mode).
    pub stack_segment: u64,
}

impl fmt::Debug for ExceptionStackFrame {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        struct Hex(u64);
        impl fmt::Debug for Hex {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "{:#x}", self.0)
            }
        }

        let mut s = f.debug_struct("ExceptionStackFrame");
        s.field("instruction_pointer", &Hex(self.instruction_pointer));
        s.field("code_segment", &Hex(self.code_segment));
        s.field("cpu_flags", &Hex(self.cpu_flags));
        s.field("stack_pointer", &Hex(self.stack_pointer));
        s.field("stack_segment", &Hex(self.stack_segment));
        s.finish()
    }
}



// dummy function
fn abort() {}

*/