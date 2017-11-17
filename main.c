/**
 * Bareflank EL2 boot stub
 * A simple program that sets up EL2 for later use by the Bareflank hypervsior.
 *
 * Copyright (C) Assured Information Security, Inc.
 *      Author: Kate J. Temkin <temkink@ainfosec.com>
 *
 * <insert license here>
 */

#include <stdint.h>
#include <microlib.h>

#include <libfdt.h>
#include <cache.h>

#include "image.h"

/**
 * Print our intro message
 */
void intro(uint32_t el)
{

    printf("_______ _     _ _     _ __   _ ______  _______  ______        _______ __   _ _______");
    printf("   |    |_____| |     | | \\  | |     \\ |______ |_____/ |      |_____| | \\  | |______");
    printf("   |    |     | |_____| |  \\_| |_____/ |______ |    \\_ |_____ |     | |  \\_| |______");
    printf("                                         --insert pony ascii here--                 ");
    printf("");
    printf("\n\nInitializing Bareflank stub...\n");
    printf("  current execution level:               EL%u\n", el);
    printf("  hypervisor applications supported:     %s\n", (el == 2) ? "YES" : "NO");

}

/**
 * Triggered on an unrecoverable condition; prints an error message
 * and terminates execution.
 */
void panic(const char * message)
{
    printf("\n\n");
    printf("-----------------------------------------------------------------\n");
    printf("PANIC: %s\n", message);
    printf("-----------------------------------------------------------------\n");

    // TODO: This should probably induce a reboot,
    // rather than sticking here.
    while(1);
}

void main(void * fdt, uint32_t el)
{
    // Print our intro text...
    intro(el);

    // ... and ensure we're in EL2.
    if (el != 2) {
        panic("The bareflank stub must be launched from EL2!");
    }

    // Tasks we have to do:
    // - Set up the hypercall table so we can return to EL2.
    // - LIKELY: Set up the second-level page table to isolate out the EL2 memory.
    // - Set up the EL1 stack and enough state so we can pop down to EL1.
    // - Switch down to EL1.
    // - Find the kernel / ramdisk / etc. in the FDT we were passed.
    // - Patch the FDT to remove the nodes we're consuming (e.g. kernel location)
    //   and to pass in e.g. the ramdisk in the place where it should be.
    // - Launch our next-stage (e.g. Linux) kernel.
    panic("This code isn't complete!");
}
