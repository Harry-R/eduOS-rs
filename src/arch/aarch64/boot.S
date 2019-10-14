/*
 * Copyright (C) 2018 bzt (bztsrc@github)
 * Copyright (c) 2018 Andre Richter <andre.o.richter@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 */
.section ".text.boot"

.global _start

.macro ALIGN
.align 4
.endm

.macro END name
	.size name, .-name
.endm

.macro ENDPROC name
// type name, @function; END name
.endm

.macro ENTRY name
	.globl name;
	ALIGN;
	name:
.endm

// TODO: print message from boot? Error handler?

// Marco definition
/*
 * There are no PUSH/POP instruction in ARMv8.
 * Use STR and LDR for stack accesses.
 */
.macro push, xreg
str     \xreg, [sp, #-8]!
.endm

.macro pop, xreg
ldr     \xreg, [sp], #8
.endm


_start:
    // read cpu id, stop slave cores
    mrs     x1, mpidr_el1
    and     x1, x1, #3
    cbz     x1, 2f
    // cpu id > 0, stop
1:  wfe
    b       1b
2:  // cpu id == 0

    // init 1G stack stack in RAM area (>0x40000000 for qemu virt device)
    movz x1, 0x5000, lsl 16
    mov sp, x1

    // init exception handler

    // macro for saving context on exception
    .macro trap_entry, el
         stp x29, x30, [sp, #-16]!
         stp x27, x28, [sp, #-16]!
         stp x25, x26, [sp, #-16]!
         stp x23, x24, [sp, #-16]!
         stp x21, x22, [sp, #-16]!
         stp x19, x20, [sp, #-16]!
         stp x17, x18, [sp, #-16]!
         stp x15, x16, [sp, #-16]!
         stp x13, x14, [sp, #-16]!
         stp x11, x12, [sp, #-16]!
         stp x9, x10, [sp, #-16]!
         stp x7, x8, [sp, #-16]!
         stp x5, x6, [sp, #-16]!
         stp x3, x4, [sp, #-16]!
         stp x1, x2, [sp, #-16]!

         mrs x22, tpidr_el0
         stp x22, x0, [sp, #-16]!

         mrs x22, elr_el1
         mrs x23, spsr_el1
         stp x22, x23, [sp, #-16]!
    .endm

    // macro for restoring context after exception
    .macro trap_exit, el
         ldp x22, x23, [sp], #16
         msr elr_el1, x22
         msr spsr_el1, x23

         ldp x22, x0, [sp], #16
         msr tpidr_el0, x22

         ldp x1, x2, [sp], #16
         ldp x3, x4, [sp], #16
         ldp x5, x6, [sp], #16
         ldp x7, x8, [sp], #16
         ldp x9, x10, [sp], #16
         ldp x11, x12, [sp], #16
         ldp x13, x14, [sp], #16
         ldp x15, x16, [sp], #16
         ldp x17, x18, [sp], #16
         ldp x19, x20, [sp], #16
         ldp x21, x22, [sp], #16
         ldp x23, x24, [sp], #16
         ldp x25, x26, [sp], #16
         ldp x27, x28, [sp], #16
         ldp x29, x30, [sp], #16
    .endm


    /*
     * SYNC & IRQ exception handler.
     */
    .align 6
    el1_irq:
          trap_entry 1
          mov     x0, sp
          bl      do_irq
          cmp     x0, 0
          b.eq    1f
         // change back to old stack frame
          mov x1, sp
          str x1, [x0]                  /* store old sp */
          bl get_current_stack          /* get new sp   */
          mov sp, x0

          /* call cleanup code */
          bl finish_task_switch

    1:    trap_exit 1
          eret
    ENDPROC el1_irq

    .align 6
    el1_fiq:
          trap_entry 1
          mov     x0, sp
          // TODO: implement fiq handling
          bl      do_irq
          cmp     x0, 0
          b.eq    1f

          mov x1, sp
          str x1, [x0]                  /* store old sp */
          bl get_current_stack          /* get new sp   */
          mov sp, x0

          /* call cleanup code */
          bl finish_task_switch

    1:    trap_exit 1
          eret
    ENDPROC el1_fiq

    .align 6
    el1_error:
          trap_entry 1
          mov     x0, sp
          bl      do_error
          trap_exit 1
          eret
    ENDPROC el1_error

    /*
     * Exception vector entry
     */
    .macro ventry label
    .align  7
    b       \label
    .endm

    .macro invalid, reason
    mov     x0, sp
    mov     x1, #\reason
    b       do_bad_mode
    .endm

    el0_sync_invalid:
       invalid 0
    ENDPROC el0_sync_invalid

    el0_irq_invalid:
       invalid 1
    ENDPROC el0_irq_invalid

    el0_fiq_invalid:
       invalid 2
    ENDPROC el0_fiq_invalid

    el0_error_invalid:
       invalid 3
    ENDPROC el0_error_invalid

    el1_sync_invalid:
       invalid 0
    ENDPROC el1_sync_invalid

    el1_irq_invalid:
       invalid 1
    ENDPROC el1_irq_invalid

    el1_fiq_invalid:
       invalid 2
    ENDPROC el1_fiq_invalid

    el1_error_invalid:
       invalid 3
    ENDPROC el1_error_invalid


    // see https://developer.arm.com/docs/100933/latest/aarch64-exception-vector-table
    .align  11
    ENTRY(vector_table)
    /* Current EL with SP0 */
    ventry el1_sync_invalid	        // Synchronous EL1t
    ventry el1_irq_invalid	        // IRQ EL1t
    ventry el1_fiq_invalid	        // FIQ EL1t
    ventry el1_error_invalid        // Error EL1t

    /* Current EL with SPx */
    ventry el1_sync                 // Synchronous EL1h
    ventry el1_irq                  // IRQ EL1h
    ventry el1_fiq                  // FIQ EL1h
    ventry el1_error                // Error EL1h

    /* Lower EL using AArch64 */
    ventry el0_sync_invalid         // Synchronous 64-bit EL0
    ventry el0_irq_invalid          // IRQ 64-bit EL0
    ventry el0_fiq_invalid          // FIQ 64-bit EL0
    ventry el0_error_invalid        // Error 64-bit EL0

    /* Lower EL using AArch32 */
    ventry el0_sync_invalid         // Synchronous 32-bit EL0
    ventry el0_irq_invalid          // IRQ 32-bit EL0
    ventry el0_fiq_invalid          // FIQ 32-bit EL0
    ventry el0_error_invalid        // Error 32-bit EL0
    END vector_table

    // jump to Rust code, should not return
    b       init
    // for failsafe, halt this core too
    // TODO: check branch dest.: Why jump to 1 back?
    b       1b
