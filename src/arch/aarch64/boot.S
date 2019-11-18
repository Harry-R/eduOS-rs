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
.global _reschedule

.macro ALIGN
.align 4
.endm

.macro END name
	.size name, .-name
.endm

.macro ENDPROC name
.type name, @function;
END name
.endm

// Prints a character to serial console
.macro PRINTC char
    movz x8, 0x900, lsl 16
    movz x7, \char
    str x7, [x8]
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

    // debug output A
    PRINTC 0x41

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

    /* Set exception table */
    ldr x0, =vector_table
    msr vbar_el1, x0

    // debug output B
    PRINTC 0x42

    // jump to Rust code, should not return
    b       init
    // for failsafe, halt this core too
3:  wfe
    b       3b

    // macro for saving context on exception
    .macro trap_entry
         stp x30, x31, [sp, #-16]!
         stp x28, x29, [sp, #-16]!
         stp x26, x27, [sp, #-16]!
         stp x24, x25, [sp, #-16]!
         stp x22, x23, [sp, #-16]!
         stp x20, x21, [sp, #-16]!
         stp x18, x19, [sp, #-16]!
         stp x16, x17, [sp, #-16]!
         stp x14, x15, [sp, #-16]!
         stp x12, x13, [sp, #-16]!
         stp x10, x11, [sp, #-16]!
         stp x8, x9, [sp, #-16]!
         stp x6, x7, [sp, #-16]!
         stp x4, x5, [sp, #-16]!
         stp x2, x3, [sp, #-16]!
         stp x0, x1, [sp, #-16]!

         mrs x22, elr_el1
         mrs x23, spsr_el1
         stp x22, x23, [sp, #-16]!
    .endm

    // macro for restoring context after exception
    .macro trap_exit
         ldp x22, x23, [sp], #16
         msr elr_el1, x22
         msr spsr_el1, x23

         ldp x0, x1, [sp], #16
         ldp x2, x3, [sp], #16
         ldp x4, x5, [sp], #16
         ldp x6, x7, [sp], #16
         ldp x8, x9, [sp], #16
         ldp x10, x11, [sp], #16
         ldp x12, x13, [sp], #16
         ldp x14, x15, [sp], #16
         ldp x16, x17, [sp], #16
         ldp x18, x19, [sp], #16
         ldp x20, x21, [sp], #16
         ldp x22, x23, [sp], #16
         ldp x24, x25, [sp], #16
         ldp x26, x27, [sp], #16
		 ldp x28, x29, [sp], #16
		 ldp x30, xzr, [sp], #16
    .endm


    /*
     * SYNC & IRQ exception handler.
     */

     .align 6
    el1_sync:
          trap_entry
          mov     x0, sp
          bl      do_sync
		  trap_exit
          eret
    ENDPROC el1_sync

    .align 6
    el1_irq:
          trap_entry
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
          // Cleanup not necessary here
          //bl finish_task_switch

1:        trap_exit
          eret
    ENDPROC el1_irq

    .align 6
    el1_fiq:
          trap_entry
          mov     x0, sp
          bl      do_fiq
          cmp     x0, 0
          b.eq    1f

          mov x1, sp
          str x1, [x0]                  /* store old sp */
          bl get_current_stack          /* get new sp   */
          mov sp, x0

          /* call cleanup code */
          // Cleanup not necessary here
          // bl finish_task_switch

PRINTC 0x42

1:        trap_exit
          eret
    ENDPROC el1_fiq

    .align 6
    _reschedule:
          trap_entry
          bl      call_scheduler
          cmp     x0, 0
          b.eq    1f

          mov x1, sp
          str x1, [x0]                  /* store old sp */
          bl get_current_stack          /* get new sp   */
          mov sp, x0

          /* call cleanup code */
          // Cleanup not necessary here

1:        trap_exit
          ret
    ENDPROC _reschedule

    .align 6
    el1_error:
          trap_entry
          mov     x0, sp
          bl      do_error
          trap_exit
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
       invalid 10
    ENDPROC el1_sync_invalid

    el1_irq_invalid:
       invalid 11
    ENDPROC el1_irq_invalid

    el1_fiq_invalid:
       invalid 12
    ENDPROC el1_fiq_invalid

    el1_error_invalid:
       invalid 13
    ENDPROC el1_error_invalid


    // see https://developer.arm.com/docs/100933/latest/aarch64-exception-vector-table
    .align  11
    .globl vector_table;
	ALIGN;
    vector_table:
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
