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
#include <cache.h>

#include "image.h"

/**
 * Print our intro message. This is surprisignly nice as a
 * boundary between serial output, as we're the firt real serial
 * output on (re)boot.
 */
void intro(uint32_t el)
{
    printf("      _ _          _                          \n");
    printf("     | (_)        | |                         \n");
    printf("   __| |_ ___  ___| |__   __ _ _ __ __ _  ___ \n");
    printf("  / _` | / __|/ __| '_ \\ / _` | '__/ _` |/ _ \\\n");
    printf(" | (_| | \\__ \\ (__| | | | (_| | | | (_| |  __/\n");
    printf("  \\__,_|_|___/\\___|_| |_|\\__,_|_|  \\__, |\\___|\n");
    printf("                                    __/ |     \n");
    printf("   depthcharge -> xen adapter      |___/   v0 \n");

    printf("\n\nInitializing discharge...\n");
    printf("  current execution level:               %u\n", el);
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



/**
 * Main task for loading the system's device tree.
 */
void load_device_tree(void *fdt)
{
    int rc;
    char * fdt_raw = fdt;

    printf("\nLoading device tree...\n");
    rc = ensure_image_is_accessible(fdt);

    printf("  flattened device tree resident at:     0x%p\n", fdt);
    printf("  flattened device tree magic is:        %02x%02x%02x%02x\n", fdt_raw[0], fdt_raw[1], fdt_raw[2], fdt_raw[3]);
    printf("  flattened device tree is:              %s (%d)\n", rc == SUCCESS ? "valid" : "INVALID", rc);

    if(rc != SUCCESS)
        panic("Cannot continue without a valid device tree.");

    printf("  flattened device size:                 %d bytes \n", fdt_totalsize(fdt));
}

void launch_kernel(const void * kernel_addr)
{
    void (*kernel)(void) = kernel_addr;

    printf("\n Launching Xen...\n");
    kernel();
}


void main(void * fdt, uint32_t el)
{
    const void *fit_image;
    const void *xen_kernel, *target_fdt, *dom0_kernel;

    intro(el);

    load_device_tree(fdt);

    // Find the fit image, which contains our Xen/Linux payloads.
    fit_image = find_fit_subimage(fdt);
    if(!fit_image)
        panic("Could not find any images to load.");

    // Extract/relocate the Xen kernel from our image.
    printf("\nLoading Xen kernel image...\n");
    xen_kernel = load_image_component(fit_image, "/images/xen_kernel@1");
    if(!xen_kernel)
        panic("Could not load the Xen kernel!");

    // Extract/relocate the target FDT.
    printf("\nLoading target device tree...\n");
    target_fdt = load_image_component(fit_image, "/images/fdt@1");
    if(!target_fdt)
        panic("Could not load the target device tree!");

    // Extract/relocate the dom0 kernel.
    printf("\nLoading Linux kernel image...\n");
    dom0_kernel = load_image_component(fit_image, "/images/linux_kernel@1");
    if(!dom0_kernel)
        panic("Could not load the Linux kernel!");


    printf("\nWARNING: Not fully implemented. Without device tree mods\n");
    printf("          expect Xen to crash and burn.\n");

    //Boot into the Xen kernel.
    launch_kernel(xen_kernel);

    // If we've made it here, we failed to boot, and we can't recover.:
    panic("Discharge terminated without transferring control to Xen!");
}
