/**
 * Bareflank EL2 boot stub
 * A simple program that sets up EL2 for later use by the Bareflank hypervsior.
 *
 * Copyright (C) Assured Information Security, Inc.
 *      Author: Kate J. Temkin <k@ktemkin.com>
 *
 * <insert license here>
 */

#include <stdint.h>
#include <microlib.h>

#include <libfdt.h>
#include <cache.h>

#include "image.h"


void switch_to_el1(void * fdt);
void main_el1(void * fdt, uint32_t el);

/**
 * Print our intro message
 */
void intro(uint32_t el)
{

    printf("_______ _     _ _     _ __   _ ______  _______  ______        _______ __   _ _______\n");
    printf("   |    |_____| |     | | \\  | |     \\ |______ |_____/ |      |_____| | \\  | |______\n");
    printf("   |    |     | |_____| |  \\_| |_____/ |______ |    \\_ |_____ |     | |  \\_| |______\n");
    printf("                                         --insert pony ascii here--                 \n");
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


/**
 * Main task for loading the system's device tree.
 */
void load_device_tree(void *fdt)
{
    int rc;
    char * fdt_raw = fdt;

    printf("\nFinding device tree...\n");
    rc = ensure_image_is_accessible(fdt);

    printf("  flattened device tree resident at:     0x%p\n", fdt);
    printf("  flattened device tree magic is:        %02x%02x%02x%02x\n", fdt_raw[0], fdt_raw[1], fdt_raw[2], fdt_raw[3]);
    printf("  flattened device tree is:              %s (%d)\n", rc == SUCCESS ? "valid" : "INVALID", rc);

    if(rc != SUCCESS)
        panic("Cannot continue without a valid device tree.");

    printf("  flattened device size:                 %d bytes \n", fdt_totalsize(fdt));
}

/**
 * Launch an executable kernel image. Should be the last thing called by
 * Discharge, as it does not return.
 *
 * @param kernel The kernel to be executed.
 * @param fdt The device tree to be passed to the given kernel.
 */
void launch_kernel(const void *kernel, const void *fdt)
{
    const uint32_t *kernel_raw = kernel;

    // Construct a function pointer to our kernel, which will allow us to
    // jump there immediately. Note that we don't care what this leaves on
    // the stack, as either our entire stack will be ignored, or it'll
    // be torn down by the target kernel anyways.
    void (*target_kernel)(const void *fdt) = kernel;

    // Validate that we seem to have a valid kernel image, and warn if
    // we don't.
    if(kernel_raw[14] != 0x644d5241) {
        printf("! WARNING: Kernel image has invalid magic (0x%x)\n", kernel_raw);
        printf("!          Attempting to boot anyways.\n");
    }

    printf("\nLaunching hardware domain kernel...\n");
    target_kernel(fdt);
}

/**
 * Locates an image already loaded by the previous-stage bootloader from the
 * FDT provided by that bootloader.
 *
 * @param fdt The FDT passed from the previous-stage bootloader.
 * @param path The path to look for the given image.
 *    TODO: replace this with a compatible string, and search for it
 * @param description String description of the image, for error messages.
 * @param out_location Out argument; if non-null, will be populated with the
 *    starting location of the relevant image.
 * @param out_size Out argument; if non-null, will be populated with the
 */
int find_image_verbosely(void *fdt, const char *path, const char *description,
        void ** out_kernel_location, size_t *out_kernel_size)
{
    int kernel_node, rc;

    printf("\nFinding %s image...\n", description);

    // FIXME: Currently, for this early code, we assume the module paths
    // as passed by Discharge-- but for later code, we'll want to filter
    // through all of the nodes in the FDT and search for the appropriate
    // compatible strings. See Xen's early boot for an example of how to do this.
    kernel_node = find_node(fdt, path);
    if (kernel_node < 0) {
        printf("ERROR: Could not locate the %s image! (%d)\n", description, -kernel_node);
        printf("Did the previous stage bootloader not provide it?\n");
        return -kernel_node;
    }

    // Print where we found the image description in the FDT.
    printf("  image information found at offset:     %d\n", kernel_node);

    // Read the size of the location and size of the kernel.
    rc = get_image_extents(fdt, kernel_node, "kernel", out_kernel_location, out_kernel_size);
    if(rc != SUCCESS) {
        printf("ERROR: Could not locate the %s image! (%d)", description, rc);
    }

    // Printt the arguments we're fetching.
    if(out_kernel_location) {
        printf("  image resident at:                     0x%p\n", *out_kernel_location);
    }
    if(out_kernel_size) {
        printf("  image size:                            0x%p\n", *out_kernel_size);
    }

    return SUCCESS;
}

/**
 * Core section of the Bareflank stub-- sets up the hypervisor from up in EL2.
 */
void main(void *fdt, uint32_t el)
{

    // Print our intro text...
    intro(el);

    // ... and ensure we're in EL2.
    if (el != 2) {
        panic("The bareflank stub must be launched from EL2!");
    }

    // TODO:
    // - Set up the hypercall table so we can return to EL2.
    // - LIKELY: Set up the second-level page table to isolate out the EL2 memory.
    // - Set up the EL1 stack and enough state so we can pop down to EL1.

    // - Switch down to EL1.
    printf("\nSwitching to EL1...\n");
    switch_to_el1(fdt);
}


/**
 * Secondary section of the Bareflank stub, executed once we've surrendered
 * hypervisor privileges.
 */
void main_el1(void * fdt, uint32_t el)
{
    int rc;

    void * kernel_location;

    // Validate that we're in EL1.
    printf("Now executing from EL%d!\n", el);
    if(el != 1) {
        panic("Executing with more privilege than we expect!");
    }

    // Load the device tree.
    load_device_tree(fdt);

    // Find the kernel / ramdisk / etc. in the FDT we were passed.
    rc = find_image_verbosely(fdt, "/module@0", "kernel", &kernel_location, NULL);
    if (rc) {
        panic("Could not find a kernel to launch!");
    }

    // TODO:
    // - Patch the FDT's memory nodes and remove the memory we're using.
    // - Patch the FDT to remove the nodes we're consuming (e.g. kernel location)
    //   and to pass in e.g. the ramdisk in the place where it should be.

    // - Launch our next-stage (e.g. Linux) kernel.
    launch_kernel(kernel_location, fdt);

    // If we've made it here, we failed to boot, and we can't recover.
    panic("The Bareflank stub terminated without transferring control to the first domain!");

}
