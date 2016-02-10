/*
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

#include <inttypes.h>

/**
 * Prints a single character (synchronously) via serial.
 *
 * @param c The character to be printed
 */
void putc(char c)
{
    asm volatile(
          "mov x0, %0\n\t"
          "bl  _putc\n\t"
          :: "r" (c) : "x0", "x1", "x30"
    );
}

/**
 * Prints a string (synchronously) via serial.
 *
 * @param s The string to be printed; must be null terminated.
 */
void puts(char * s)
{
    while(*s) {

        // If we're about to send a newline, prefix it with a carriage return.
        // This makes our puts behave like a normal console puts.
        if(*s == '\n')
            putc('\r');

        putc(*s);
        ++s;
    }
}

void main(void)
{
    puts("Hello, from Discharge!\n");
    while(1) {}
}
