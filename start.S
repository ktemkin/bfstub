/**
 * Bareflank EL2 boot stub
 * A simple program that sets up EL2 for later use by the Bareflank hypervsior.
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

