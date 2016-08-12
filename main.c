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

    printf("\nLoading device tree...\n");
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
    const char * fdt_raw = fdt;

    // Construct a function pointer to our kernel, which will allow us to
    // jump there immediately. Note that we don't care what this leaves on
    // the stack, as either our entire stack will be ignored, or it'll
    // be torn down by the target kernel anyways.
    void (*target_kernel)(const void *fdt) = kernel;

    // Perform a quick sanity check of the given FDT.
    if(fdt_check_header(fdt) != SUCCESS) {
        printf("WARNING: The loaded device tree seems to be invalid!"
            " (magic = %02x%02x%02x%02x)\n", fdt_raw[0], fdt_raw[1], fdt_raw[2], fdt_raw[3]);
        printf("         Continuing, but this will likely result in a crash.\n\n");
    }

    printf("\n Launching Xen...\n");
    target_kernel(fdt);
}

/**
 * Extract and relocate the image component at the proivded image path,
 * using the load address specified in the image.
 *
 * @param image The image from which the component should be extracted.
 * @param path The path in the image at which the component should be located.
 * @param description A short description of the image for verbose output.
 *
 * @return The component, on successful load. Panics on failure, halting the CPU.
 */
void * load_image_component_verbosely(const void * image,
    const char * path, const char * description, int * size)
{
    void * component;

    printf("\nLoading %s image...\n", description);
    component = load_image_component(image, path, size);
    if(!component)
        panic("Failed to load a required image!");

    return component;
}


/**
 * Extract and relocate the image component at the proivded image path,
 * using the load address specified in the image.
 *
 * @param image The image from which the component should be extracted.
 * @param path The path in the image at which the component should be located.
 * @param description A short description of the image for verbose output.
 *
 * @return The component, on successful load. Panics on failure, halting the CPU.
 */
void * load_image_fdt_verbosely(const void * image,
    const char * path, const char * description)
{
    void * component;

    printf("\nLoading %s image...\n", description);
    component = load_image_fdt(image, path);
    if(!component)
        panic("Failed to load a required image!");

    return component;
}


void main(void * fdt, uint32_t el)
{
    const void *fit_image;
    void *xen_kernel, *target_fdt, *dom0_kernel;
    int dom0_kernel_size;
    int rc;

    intro(el);

    load_device_tree(fdt);

    // Find the fit image, which contains our Xen/Linux payloads.
    fit_image = find_fit_subimage(fdt);
    if(!fit_image)
        panic("Could not find any images to load.");

    // Extract the images that we'll need to boot from.
    //
    // Note that we have to be a bit picky about this order, as we don't have much space to operate in,
    // and thus it may be acceptable to have the huge dom0 image trample the source images if it's the
    // last to load. We'll work to keep that as the last loaded component to allow this freedom.
    xen_kernel  = load_image_component_verbosely(fit_image, "/images/xen_kernel@1", "Xen kernel", NULL);
    target_fdt  = load_image_component_verbosely(fit_image, "/images/fdt@1", "device tree", NULL);
    dom0_kernel = load_image_component_verbosely(fit_image, "/images/linux_kernel@1", "dom0 kernel", &dom0_kernel_size);

    // TODO: Add ramdisk support.

    // Update the module information we'll pass to Xen.
    rc = update_fdt_for_xen(target_fdt, dom0_kernel, dom0_kernel_size);
    if(rc != SUCCESS)
      panic("Could not populate device tree with the dom0 location!");

    // Finally, we'll copy over the contents of our memory node, copying the bootloader-adjusted
    // scope of the system memory. It's important that we get this right, as the system can carve
    // out regions during startup (e.g. for the Secure World), and if we don't respect this, we'll
    // wind up with unwriteable memory and/or with memory that's trashed by other systems.
    // (For now, we skip this if we weren't launch using a FIT launcher; this maintains consistent
    // behavior when testing this from u-boot using extlinux/bootu. This may change in the future.)
    if(fdt != fit_image) {
      rc = update_fdt_memory(target_fdt, fdt);

      if(rc != SUCCESS)
          panic("Could not update the new FDT with updated memory ranges!");
    }

    // Finally, boot into the Xen kernel.
    launch_kernel(xen_kernel, target_fdt);

    // If we've made it here, we failed to boot, and we can't recover.
    panic("Discharge terminated without transferring control to Xen!");
}
