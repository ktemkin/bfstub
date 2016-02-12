/**
 * Discharge Boot Adapter: a utility to boot Xen from Depthcharge on AArch64
 *
 * Copyright (C) Assured Information Security, Inc.
 *      Author: Kyle J. Temkin <temkink@ainfosec.com>
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a 
 *  copy of this software and associated documentation files (the "Software"), 
 *  to deal in the Software without restriction, including without limitation 
 *  the rights to use, copy, modify, merge, publish, distribute, sublicense, 
 *  and/or sell copies of the Software, and to permit persons to whom the 
 *  Software is furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in 
 *  all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS 
 *  OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING 
 *  FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER 
 *  DEALINGS IN THE SOFTWARE.
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
        .quad   0               // reserved
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

