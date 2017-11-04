/**
 * Routines to handle "subimage" payloads.
 *
 * Copyright (C) Assured Information Security, Inc.
 *      Author: ktemkin <temkink@ainfosec.com>
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

#ifndef __SUBIMAGE_H__
#define __SUBIMAGE_H__

#include <microlib.h>
#include <libfdt.h>

const void * find_fit_subimage(void *fdt);

/**
 * Ensures that a valid FDT/image is accessible for the system, performing any
 * steps necessary to make the image accessible, and validating the device tree.
 *
 * @return SUCCESS, or an FDT error code.
 */
int ensure_image_is_accessible(const void *image);


/**
 * Fetches the information necessary to load a subcomponent into memory,
 * querying the properites from the provided FIT image.
 *
 * @param image The image from which components are to be loaded.
 * @param path The string path to the component of the FIT image, e.g.
 *    "/images/kernel@0"
 * @param out_load_location Out argument; receives a pointer to the physical
 *    address to which the subcomponent wants to be loaded.
 * @param out_data_location Out argument; receives a pointer to the physical
 *    address at which the data to be loaded is currently resident.
 * @param out_size Out argument; receives the size of the subcomponent.
 * @param node_offset Optional out argument. If non-null, receives the location
 *    of the node that describes the given subcomponent, for furhter processing.
 *
 * @return SUCCESS on success, or an error code on failure.
 */
int get_subcomponent_information(const void *image, const char *path,
    void **out_load_location, void const**out_data_location, int *out_size,
    int * node_offset);


/**
 * Loads an subimage component into its final execution location, and returns a
 * pointer to the completed binary. Performs only basic sanity checking.
 *
 * @param image The image from which the blob should be extracted.
 * @param path The path to the node that represents the given image.
 * @param size If non-NULL, this out argument will be popualted with the
 *    loaded image's size.
 * @return The address of the component, or NULL on error.
 */
void * load_image_component(const void *image, const char * path, int * size);


/**
 * Updates the provided FDT to contain information as to the in-memory location
 * of the linux kernel to be used dom0.
 *
 * @param fdt The target device tree to be updated.
 * @param module The address at which the releavant module resides in memory.
 *    Should be below 4GiB, as this is what Xen accepts.
 * @param compatible The module string, which describes the string that will be
 *    added to Xen. Usually in the format "multiboot,<type>", where type
 *    is e.g. 'kernel'.
 * @param size The size of the linux kernel, in bytes.
 *
 * @return SUCCESS on SUCCESS, or an error code on failure.
 */
int update_fdt_for_xen(void *fdt, const void *module, const int size,
    const char *compatible, const char *module_node_name);


/**
 * Adjust the target FDT's memory to match the memory regions provided by the bootloader.
 * This accounts for any memory set aside by the bootloader, e.g. for the secure world.
 * See the caveat in update_fdt_for_xen.
 *
 * @param fdt The FDT to be updated.
 *
 * @return SUCCESS, or an error code on failure
 */
int update_fdt_memory(void *target_fdt, void *source_fdt);


/**
 * Loads an subimage device tree into its final execution location, and returns
 * a pointer to the completed binary. Similar to load_image_component, but uses
 * FDT unpacking methods to create a new FDT in the target location, allowing
 * the FDT to expand into the free space.
 *
 * Expansion is controlled by the "extra-space" node in the subimage tree.
 *
 * @param image The image from which the blob should be extracted.
 * @param path The path to the node that represents the given image.
 * @return The address of the component, or NULL on error.
 */
void * load_image_fdt(const void *image, const char *path);


/**
 * Small convenience function that reads the desired amount of extra space
 * for a loaded FDT, given a pointer to the property that describes it.
 *
 * This helper exists to simplify testing; as this method can be easily
 * mocked, where a dereference can't easily be omitted.
 */
int __read_extra_space_from_fdt(const uint32_t *extra_space_location);

#endif
