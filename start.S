/*
 * Copyright (C) 2016 Assured Information Security 
 *  Author: Kyle J. Temkin <temkink@ainfosec.com>
 * Copyright (C) 2014 Andrei Warkentin <andrey.warkentin@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston,
 * MA 02111-1307 USA
 */

#define SERIAL_BASE 0x70006000

.globl _header
/*
 * x0 contains the FDT blob PA, which we don't use
 */
_header:
        b       _start          // branch to kernel start, magic
        .long   0                 // reserved
        .quad   0x0               // Image load offset from start of RAM, unused
        .quad   0                 // reserved
        .quad   0                 // reserved
        .quad   0                 // reserved
        .quad   0                 // reserved
        .quad   0                 // reserved
        .byte   0x41              // Magic number, "ARM\x64"
        .byte   0x52
        .byte   0x4d
        .byte   0x64
        .word   0                 // reserved
_start:

        // TODO: Store away our pointers (fdt, ramdisk?) in a c-accesible
        // location.

        // Create a simple stack for our C program, and jump to it.
        ldr     x0, =stack_end
        mov     sp, x0

        // Run the main discharge routine. This shouldn't return.
        b       main

        // We shouldn't ever reach here; trap.
1:      b       1b


/*
 * Print a char in x0.
 *
 * Clobbers x0, x1.
 */
.global _putc
_putc:
        ldr     x1, =SERIAL_BASE
        strb    w0, [x1]
1:      ldrb    w0, [x1, #20]     // LSR
        tbz     w0, #5, 1b        // THRE == 0
        ret

.section .data
.align 16
stack:
        .fill 16384, 8, 0
stack_end:

