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
 * Finds the chosen node in the Discharged FDT, which contains
 * e.g. the location of our final payload.
 */
int find_chosen_node(void * fdt)
{
    int node = fdt_path_offset(fdt, "/chosen");

    // If we weren't able to get the chosen node, return NULL.
    if(node < 0) 
        printf("ERROR: Could not find chosen node! (%d)", node);
    else
        printf("  chosen node found at offset:           %d\n", node);

    return node;
}


/**
 * Converts a 32-bit devicetree location (e.g. our subimage location)
 * into a full 64-bit address.
 */
void * location_from_devicetree(uint32_t metalocation)
{
    return (void *)(uintptr_t)fdt32_to_cpu(metalocation);
}


/**
 * Finds the address of the FIT subimage that contains our payloads.
 *
 * @param fdt The high-level flattened device tree for the system.
 * @return The address of the subimage, or NULL if no subimage could be loaded.
 */
const void * find_fit_subimage(void *fdt)
{
    int rc;
    int chosen_node, subimage_location_size;

    // Unfortunately, image locations received in the FDT are stored as 32-bit
    // integers for backwards compatibility. We'll have to expand this out
    // to a full 64-bit image ourselves.
    const uint32_t const * subimage_location;
    const char * subimage;

    // Find the node that describes our main payload.
    printf("\nExtracting main fit image...\n");
    chosen_node = find_chosen_node(fdt);

    if(chosen_node < 0)
        return NULL;

    // Find the location of the initrd property, which holds our subimage...
    subimage_location = fdt_getprop(fdt, chosen_node, "linux,initrd-start", &subimage_location_size);
    if(subimage_location_size <= 0) {
        printf("ERROR: Could not find the subimage node! (%d)", subimage_location_size);
        return NULL;
    }

    // If we've found a subimage, print out its information.
    subimage = location_from_devicetree(*subimage_location);
    printf("  description of subimage is:            %d bytes\n", subimage_location_size);
    printf("  description location is:               0x%p\n",  subimage_location);
    printf("  subimage location is:                  0x%p\n",  subimage);
    printf("  subimage magic is:                     %02x%02x%02x%02x\n", subimage[0], subimage[1], subimage[2], subimage[3]);

    // Ensure that the subimage is accessible.
    rc = ensure_image_is_accessible(subimage);
    if(rc)
        return NULL;

    printf("  subimage is:                           %s (%d)\n", rc == SUCCESS ? "valid" : "INVALID", rc);
    printf("  subimage size:                         %d bytes \n", fdt_totalsize(subimage));

    // Otherwise, return the location of our subimage.
    return subimage;
}


/**
 * Finds the chosen node in the Discharged FDT, which contains
 * e.g. the location of our final payload.
 */
int find_node(const void * image, const char * path)
{
    int node = fdt_path_offset(image, path);

    // If we weren't able to get the chosen node, return NULL.
    if(node < 0)
        printf("ERROR: Could not find xen kernel in subimage! (%d)", node);
    else
        printf("  image node found at offset:            %d\n", node);

    return node;
}


/**
 * Loads an subimage componen tinto its final execution location, and returns a
 * pointer to the completed binary. Performs only basic sanity checking.
 *
 * @param image The image from which the blob should be extracted.
 * @param path The path to the node that represents the given image.
 * @return The address of the component, or NULL on error.
 */
const void * load_image_component(const void *image, const char * path)
{
    const uint32_t const *load_information_location;
    const void *data_location;
    void *load_location;

    int node, load_information_size, size;

    // Find the FIT node that describes the image.
    node = find_node(image, path);
    if(node < 0)
        return NULL;

    // Locate the node that specifies where we should load this image from.
    data_location = fdt_getprop(image, node, "data", &size);
    if(size <= 0) {
        printf("ERROR: Couldn't find the data to load! (%d)", size);
        return NULL;
    }

    // Print out statistics regarding the loaded image...
    printf("  loading image from:                    0x%p\n", data_location);
    printf("  loading a total of:                    %d bytes\n", size);


    // Locate the FIT node that specifies where we should load this image component to.
    load_information_location = fdt_getprop(image, node, "load", &load_information_size);
    if(load_information_size <= 0) {
        printf("ERROR: Couldn't determine where to load to! (%d)", load_information_size);
        return NULL;
    }

    // Retrieve the load location.
    load_location = location_from_devicetree(*load_information_location);
    printf("  loading image to location:             0x%p\n", load_location);
    printf("  image will end at address:             0x%p\n", load_location + size);

    // TODO: Sanity check bounds!

    // Finally, copy the data to its final location.
    memmove(load_location, data_location, size);
    printf("  total copied:                          %d bytes\n", size);

    return load_location;
}
