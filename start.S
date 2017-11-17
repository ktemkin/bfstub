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

        // Create a simple stack for our C program, and jump to it.
        ldr     x1, =stack_end
        mov     sp, x1

        // Load the current execution level into x1; we'll need this to
        // determine whether we can continue into Xen.
        mrs     x1, CurrentEL
        lsr     x1, x1, #2

        // Clear out the system's bss. Depthcharge doesn't do this for us,
        // as it assumes we're a kernel capable of self-bootstrapping.
        stp     x0, x1, [sp, #-16]!
        bl      _clear_bss
        ldp     x0, x1, [sp], #16

        // Run the main discharge routine. This shouldn't return.
        b       main

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

