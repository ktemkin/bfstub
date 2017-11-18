/**
 * Bareflank EL2 boot stub: entry points
 * This file contains all entry points (e.g. when launching or switching ELs).
 *
 * Copyright (C) Assured Information Security, Inc.
 *      Author: Kate J. Temkin <temkink@ainfosec.com>
 *
 * <insert license here>
 */

#define SERIAL_BASE 0x70006000

.section ".text"

.globl _header
/*
 * x0 contains the FDT blob PA, which we don't use
 */
_header:
        b       _start          // branch to kernel start, magic
        .long   0               // reserved
        .quad   0               // Image load offset from start of RAM
        .quad   0x2000000       // Image size to be processed, little endian (32MiB, default for Pixel C)
        .quad   0               // reserved
        .quad   0               // reserved
        .quad   0               // reserved
        .quad   0               // reserved
        .byte   0x41            // Magic number, "ARM\x64"
        .byte   0x52
        .byte   0x4d
        .byte   0x64
        .word   0                 // reserved
_start:
        // Reminder: do not clobber x0, as it contains the location of our
        // Flattened Device Tree / FDT. If you need to use x0, stash the value
        // (e.g. on the stack), and then put it back before main.

        // Create a simple stack for the bfstub, while executing in EL2.
        ldr     x1, =el2_stack_end
        mov     sp, x1

        // Set up our vector table for EL2. This will allow us to return to
        // EL2 later, and is most of the point of this stub.
        ldr     x1, =_el2_vector_table
        msr     vbar_el2, x1

        // Load the current execution level into x1; we'll need this to
        // determine whether we can set things up.
        mrs     x1, CurrentEL
        lsr     x1, x1, #2

        // Clear out our binary's bss.
        stp     x0, x1, [sp, #-16]!
        bl      _clear_bss
        ldp     x0, x1, [sp], #16

        // Run the main routine. This shouldn't return.
        b       main

        // We shouldn't ever reach here; trap.
1:      b       1b


/*
 * Switch down to EL1 and then execute the second half of our stub.
 *
 * Obliterates the stack, but leaves the rest of memory intact. This should be
 *  fine, as we should be hiding the EL2 memory from the rest of the system.
 *
 * x0: The location of the device tree to be passed into EL0.
 */
.global switch_to_el1
switch_to_el1:

        // Set up a post-EL1-switch return address...
        ldr     x2, =_post_el1_switch
        msr     elr_el2, x2

        // .. and set up the CPSR after we switch to EL1.
        // We overwrite the saved program status register. Note that setting
        // this with the EL = EL1 is what actually causes the switch.
        mov     x2, #0x3c5     // EL1_SP1 | D | A | I | F
        msr     spsr_el2, x2

        // ... and switch down to EL1. (This essentially asks the processor
        // to switch down to EL1 and then load ELR_EL2 to the PC.)
        eret


/*
 * Entry point after the switch to EL1.
 *
 * x0: The location of the device tree.
 * x2: The C code to return to after the EL1 switch.
 */
_post_el1_switch:

        // Create a simple stack for the bfstub to use while at EL1.
        ldr     x2, =el1_stack_end
        mov     sp, x2

        // Load the current execution level into x1. We'll use this to verify
        // that we switched down to EL1.
        mrs     x1, CurrentEL
        lsr     x1, x1, #2

        // Run the main routine. This shouldn't return.
        b       main_el1

        // We shouldn't ever reach here; trap.
1:      b       1b


/*
 * Vector table for interrupts/exceptions that reach EL2.
 */
.macro  ventry  label
    .align  7
    b       \label
.endm

.align  11
_el2_vector_table:
        ventry _unhandled_vector                // Synchronous EL2t
        ventry _unhandled_vector                // IRQ EL2t
        ventry _unhandled_vector                // FIQ EL2t
        ventry _unhandled_vector                // Error EL2t

        ventry _unhandled_vector                // Synchronous EL2h
        ventry _unhandled_vector                // IRQ EL2h
        ventry _unhandled_vector                // FIQ EL2h
        ventry _unhandled_vector                // Error EL2h

        ventry _handle_hypercall                // Synchronous 64-bit EL0/EL1
        ventry _unhandled_vector                // IRQ 64-bit EL0/EL1
        ventry _unhandled_vector                // FIQ 64-bit EL0/EL1
        ventry _unhandled_vector                // Error 64-bit EL0/EL1

        ventry _unhandled_vector                // Synchronous 32-bit EL0/EL1
        ventry _unhandled_vector                // IRQ 32-bit EL0/EL1
        ventry _unhandled_vector                // FIQ 32-bit EL0/EL1
        ventry _unhandled_vector                // Error 32-bit EL0/EL1



.macro  push, xreg1, xreg2
    stp     \xreg1, \xreg2, [sp, #-16]!
.endm

.macro  pop, xreg1, xreg2
    ldp     \xreg1, \xreg2, [sp], #16
.endm

.macro  save_registers
        // General purpose registers x1 - x30
        push    x29, x30
        push    x27, x28
        push    x25, x26
        push    x23, x24
        push    x21, x22
        push    x19, x20
        push    x17, x18
        push    x15, x16
        push    x13, x14
        push    x11, x12
        push    x9,  x10
        push    x7,  x8
        push    x5,  x6
        push    x4,  x4
        push    x1,  x2

        // x0 and the el2_esr
        mrs     x20, esr_el2
        push    x20, x0

        // the el1_sp and el0_sp
        mrs     x0, sp_el0
        mrs     x1, sp_el1
        push    x0, x1

        // the el1 elr/spsr
        mrs     x0, elr_el1
        mrs     x1, spsr_el1
        push    x0, x1

        // the el2 elr/spsr
        mrs     x0, elr_el2
        mrs     x1, spsr_el2
        push    x0, x1

.endm

.macro restore_registers
        // the el2 elr/spsr
        pop     x0, x1
        msr     elr_el2, x0
        msr     spsr_el2, x1

        // the el1 elr/spsr
        pop     x0, x1
        msr     elr_el1, x0
        msr     spsr_el1, x1

        // the el1_sp and el0_sp
        pop     x0, x1
        msr     sp_el0, x0
        msr     sp_el1, x1

        // x0, and the el2_esr
        // Note that we don't restore el2_esr, as this wouldn't
        // have any meaning.
        pop    x20, x0

        // General purpose registers x1 - x30
        push    x1,  x2
        push    x4,  x4
        push    x5,  x6
        push    x7,  x8
        push    x9,  x10
        push    x11, x12
        push    x13, x14
        push    x15, x16
        push    x17, x18
        push    x19, x20
        push    x21, x22
        push    x23, x24
        push    x25, x26
        push    x27, x28
        push    x29, x30
.endm



/*
 * Handler for any vector we're not equipped to handle.
 */
_unhandled_vector:
        // TODO: Save interrupt state and turn off interrupts.
        save_registers

        // Point x0 at our saved registers, and then call our C handler.
        mov     x0, sp
        bl    unhandled_vector

        restore_registers
        eret


/*
 * Handler for any synchronous event coming from the guest (any trap-to-EL2).
 * This _stub_ only uses this to handle hypercalls-- hence the name.
 */
_handle_hypercall:
        // TODO: Save interrupt state and turn off interrupts.
        save_registers

        // Point x0 at our saved registers, and then call our C handler.
        mov     x0, sp
        bl    handle_hypercall

        restore_registers
        eret


/*
 * Print a char in x0.
 *
 * Clobbers x0, x1, x2.
 */
.global _putc
_putc:
        ldr     x1, =SERIAL_BASE
1:      ldrb    w2, [x1, #20]
        tbz     w2, #5, 1b
        strb    w0, [x1]
        ret


