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

#include "subimage.h"

int find_chosen_node(void * fdt)
{
    int node = fdt_path_offset(fdt, "/chosen");

    // If we weren't able to get the chosen node, return NULL.
    if(node < 0) 
        printf("ERROR: Could not find chosen node! (%d)", node);
    else
        printf("  chosen node found at offset:           0x%d\n", node);

    return node;
}


/**
 * Finds the address of the FIT subimage that contains our payloads.
 *
 * @param fdt The high-level flattened device tree for the system.
 * @return The address of the subimage, or NULL if no subimage could be loaded.
 */
void * find_fit_subimage(void *fdt)
{
    int chosen_node, subimage_location_size;
    const uint32_t * subimage_location;

    // Get the main location of the 
    printf("Extracting main fit image...\n");
    chosen_node = find_chosen_node(fdt);

    // Find the location of the initrd property, which holds our subimage...
    subimage_location = fdt_getprop(fdt, chosen_node, "linux,initrd-start", &subimage_location_size);
    if(subimage_location_size < 0) {
        printf("ERROR: Could not find the subimage node! (%d)", subimage_location_size);
        return 0;
    }
    else {
        printf("  subimage location size is:             0x%d\n", subimage_location_size);
        printf("  subimage location is:                  %04x%04x\n", subimage_location[0], subimage_location[1]);
    }





    return 0;
}

