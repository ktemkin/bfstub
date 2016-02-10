/**
 * Microlib:
 * simple support library providing simple stdlib equivalents for
 * discharge
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

#include <stddef.h>
#include <stdarg.h>
#include <stdint.h>

#ifndef __MICROLIB_H__
#define __MICROLIB_H__

/**
 * Standard library functions. Exactly what you'd expect.
 */
void * memcpy(void * dest, const void * src, size_t n);
void * memmove(void *dst0, const void *src0, register size_t length);
void putc(char c);
void puts(char * s);
size_t strlen(const char *s);
size_t memcmp(const void *s1, const void *s2, size_t n);
size_t strnlen(const char *s, size_t max);
void * memchr(const void *s, int c, size_t n);
void * memset(void *b, int c, size_t len);

int printf(const char *fmt, ...);


/**
 * Soft reboots the processor by jumping back to the initialization vector.
 */
void reboot(void);


#endif
