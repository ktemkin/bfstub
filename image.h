/**
 * Routines to handle "subimage" payloads.
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
 * Loads an subimage componen tinto its final execution location, and returns a
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
 * @param linux_kernel The address at which the linux kernel resides in memory.
 *    Should be below 4GiB, as this is what Xen accepts.
 * @param size The size of the linux kernel, in bytes.
 */
int update_fdt_for_xen(void *fdt, const void *linux_kernel, const int size);


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

#endif
