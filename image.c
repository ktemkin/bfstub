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

#include <microlib.h>

#include <cache.h>
#include "image.h"


/**
 * Ensures that a valid FDT/image is accessible for the system, performing any
 * steps necessary to make the image accessible, and validating the device tree.
 *
 * @return SUCCESS, or an FDT error code.
 */
int ensure_image_is_accessible(const void *image)
{
    int rc;

    // Depthcharge loads images into memory with the cache on, and doesn't
    // flush the relevant cache lines when it switches the cache off. As a
    // result, we'll need to flush the cache lines for it before we'll be able
    // to see the FDT.

    // We start by flushing our first cache line, which we assume is large
    // enough to provide the first two fields of the FDT: an 8-byte magic number,
    // and 8-byte size.
    __invalidate_cache_line(image);

    // Validate that we have a valid-appearing device tree. All images should
    // conform to the device tree standard, as they should be either Linux
    // device trees, or FIT images.
    rc = fdt_check_header(image);
    if(rc)
        return rc;

    // If we do, invalidate the remainder of its cache lines.
    __invalidate_cache_region(image, fdt_totalsize(image));

    return SUCCESS;
}


/**
 * Converts a 32-bit devicetree location (e.g. our subimage location)
 * into a full 64-bit address.
 *
 * @param metalocation The location of the location in the device tree.
 */
void * image_location_from_devicetree(const uint64_t* metalocation)
{
    uint64_t high_word_cpu, low_word_cpu;
    uintptr_t location;

    // Break the encoded location into its FDT-constituent parts.
    uint32_t *high_word_fdt = (uint32_t *) metalocation;
    uint32_t *low_word_fdt  = ((uint32_t *)metalocation) + 1;

    // Compute the full location.
    high_word_cpu  = fdt32_to_cpu(*high_word_fdt);
    low_word_cpu   = fdt32_to_cpu(*low_word_fdt);
    location       = (high_word_cpu << 32ULL) | low_word_cpu;

    return (void *)location;
}

/**
 * Converts a 32-bit devicetree location (e.g. our subimage location)
 * into a full 64-bit address.
 */
size_t image_size_from_devicetree(const uint64_t *metasize)
{
    return (size_t)image_location_from_devicetree(metasize);
}


/**
 * Finds the chosen node in the Discharged FDT, which contains
 * e.g. the location of our final payload.
 */
int find_node(const void * image, const char * path)
{
    int node = fdt_path_offset(image, path);

    // If we weren't able to get the chosen node, return NULL.
    if (node < 0)
        printf("ERROR: Could not find path %s in subimage! (%d)", path, node);
    else
        printf("  image node found at offset:            %d\n", node);

    return node;
}


/**
 * Finds the extents (start, length) of a given image, as passed from our
 * bootloader via the FDT.
 *
 * @param fdt The FDT passed from the previous-stage bootloader.
 * @param image_node The bootloader node corresponding to the relevant image.
 * @param description String description of the image, for error messages.
 * @param out_location Out argument; if non-null, will be populated with the
 *    starting location of the relevant image.
 * @param out_size Out argument; if non-null, will be populated with the
 */
int get_image_extents(const void *fdt, int image_node,
    const char *description, void **out_location, size_t *out_size)
{
    int subimage_location_size;

    // Unfortunately, image locations received in the FDT are stored as 32-bit
    // integers for backwards compatibility. We'll have to expand this out
    // to a full 64-bit image ourselves.
    const uint64_t *subimage_location;

    // Find the location of the initrd property, which holds our subimage...
    subimage_location = fdt_getprop(fdt, image_node, "reg", &subimage_location_size);
    if(subimage_location_size <= 0) {
        printf("ERROR: Could not find the %s image location! (%d)\n", description, subimage_location);
        return -subimage_location_size;
    }

    // Populate our extents, if we have a valid pointer to populate them into.
    if (out_location) {
        *out_location = image_location_from_devicetree(subimage_location);
    }
    if (out_size) {
        *out_size = image_size_from_devicetree(&subimage_location[1]);
    }


    return SUCCESS;
}

