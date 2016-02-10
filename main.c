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


#include <inttypes.h>
#include <microlib.h>
#include <libfdt.h>

// Very important code.
void intro(void)
{
    puts("      _ _          _                          \n");
    puts("     | (_)        | |                         \n");
    puts("   __| |_ ___  ___| |__   __ _ _ __ __ _  ___ \n");
    puts("  / _` | / __|/ __| '_ \\ / _` | '__/ _` |/ _ \\\n");
    puts(" | (_| | \\__ \\ (__| | | | (_| | | | (_| |  __/\n");
    puts("  \\__,_|_|___/\\___|_| |_|\\__,_|_|  \\__, |\\___|\n");
    puts("                                    __/ |     \n");
    puts("   depthcharge -> xen adapter      |___/   v0 \n");

}


void panic(const char * message)
{
    printf("\n\n");
    printf("-----------------------------\n");
    printf("PANIC: %s\n", message);
    printf("-----------------------------\n");
    while(0);
}


void main(void * fdt, uint32_t el)
{
    int validation_error;
    char * fdt_raw = fdt;

    intro();

    puts("\n\nInitializing discharge...\n");
    printf("  current execution level:               %u\n", el);
    printf("  hypervisor applications supported:     %s\n", (el == 2) ? "YES" : "NO");
    printf("  flattened device tree resident at:     0x%p\n", fdt);
    printf("  flattened device tree magic is:        %02x%02x%02x%02x\n", fdt_raw[0], fdt_raw[1], fdt_raw[2], fdt_raw[3]);

    validation_error = fdt_check_header(fdt);

    if(validation_error) {
        printf("  flattened device tree is:              INVALID (%d)\n", validation_error);
        panic("Cannot continue without a valid device tree.");
    }
    else {
        printf("  flattened device tree is:              VALID\n", validation_error);
    }


    while(1) {}
}
