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
 */
void * location_from_devicetree(uint32_t metalocation)
{
    return (void *)(uintptr_t)fdt32_to_cpu(metalocation);
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
        printf("ERROR: Could not find path %s in subimage! (%d)", path, node);
    else
        printf("  image node found at offset:            %d\n", node);

    return node;
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
    const uint32_t *subimage_location;
    const char * subimage;

    // Find the node that describes our main payload.
    printf("\nExtracting main fit image...\n");
    chosen_node = find_node(fdt, "/chosen");

    if(chosen_node < 0)
        return NULL;

    // Find the location of the initrd property, which holds our subimage...
    subimage_location = fdt_getprop(fdt, chosen_node, "linux,initrd-start", &subimage_location_size);
    if(subimage_location_size <= 0) {

        // In rarer cases (e.g. if we're launched by something other than discharge for debug),
        // we may want to use the main FDT instead of a subimage. To allow this, fail gracefully
        // by passing on the main image. If we /were/ loaded by discharge, we'll immediately fail
        // to find the Xen image, and shut down gracefully anyawy.
        printf("\n! WARNING: Couldn't find a subimage node.\n");
        printf("!          Attempting to boot using main image.\n");
        return fdt;
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
    int * node_offset)
{
    const uint32_t *load_information_location;
    const void *data_location;
    void *load_location;

    int node, load_information_size, size;

    // Before running, check all of our pointers for validity.
    if(!out_data_location || !out_load_location || !out_size)
        return -FDT_ERR_BADVALUE;

    // Find the FIT node that describes the image.
    node = find_node(image, path);
    if(node < 0)
        return node;

    // Locate the node that specifies where we should load this image from.
    data_location = fdt_getprop(image, node, "data", &size);
    if(size <= 0) {
        printf("ERROR: Couldn't find the data to load! (%d)", size);
        return size;
    }

    // Print out statistics regarding the loaded image...
    printf("  loading image from:                    0x%p\n", data_location);
    printf("  loading a total of:                    %d bytes\n", size);

    // Locate the FIT node that specifies where we should load this image component to.
    load_information_location = fdt_getprop(image, node, "load", &load_information_size);
    if(load_information_size <= 0) {
        printf("ERROR: Couldn't determine where to load to! (%d)", load_information_size);
        return load_information_size;
    }

    // Retrieve the load location.
    load_location = location_from_devicetree(*load_information_location);
    printf("  loading image to location:             0x%p\n", load_location);
    printf("  image will end at address:             0x%p\n", load_location + size);

    // Set our out arguments, and return success.
    *out_load_location = load_location;
    *out_data_location = data_location;
    *out_size = size;

    // If a node argument was provided, set the active node for further
    // processing.
    if(node_offset)
      *node_offset = node;

    return SUCCESS;
}


/**
 * Loads an subimage component into its final execution location, and returns a
 * pointer to the completed binary. Performs only basic sanity checking.
 *
 * @param image The image from which the blob should be extracted.
 * @param path The path to the node that represents the given image.
 * @param out_size If non-NULL, this out argument will be popualted with the
 *    loaded image's size.
 * @return The address of the component, or NULL on error.
 */
void * load_image_component(const void *image, const char *path, int *out_size)
{
    const void *data_location;
    void *load_location;
    int size, rc;

    // Get the information that describe where our information is located...
    rc = get_subcomponent_information(image, path, &load_location,
        &data_location, &size, NULL);

    if(rc != SUCCESS)
        return NULL;

    // We're not using the cache, but Depthcharge was before us.
    // To ensure that our next stage sees the proper memory, we'll have to
    // make sure that there are no data cache entries for the regions we're
    // about to touch. As there's no way to invalidate without cleaning via
    // virtual address (i.e. all of the evicted cache lines will be written
    // back), it's important that this runs before memmove.
    __invalidate_cache_region(load_location, size);

    // Trivial load: copy the gathered information to its final location.
    memmove(load_location, data_location, size);
    printf("  total copied:                          %d bytes\n", size);

    // ... and update our size out argument, if provided.
    if(out_size)
      *out_size = size;

    return load_location;
}

/**
 * Small convenience function that reads the desired amount of extra space
 * for a loaded FDT, given a pointer to the property that describes it.
 *
 * This helper exists to simplify testing; as this method can be easily
 * mocked, where a dereference can't easily be omitted.
 */
int __read_extra_space_from_fdt(const uint32_t *extra_space_location)
{
    return fdt32_to_cpu(*extra_space_location);
}


/**
 * Loads an subimage device tree into its final execution location, and returns
 * a pointer to the completed binary. Similar to load_image_component, but uses
 * FDT unpacking methods to create a new FDT in the target location, allowing
 * the FDT to expand into any subsequent free space.
 *
 * @param image The image from which the blob should be extracted.
 * @param path The path to the node that represents the given image.
 * @param next_component The location of the component that will follow the FDT
 *    in memory once loaded. Used to determine how much we can grow the FDT.
 * @return The address of the component, or NULL on error.
 */
void * load_image_fdt(const void *image, const char *path)
{
    const uint32_t *extra_space_location;
    const void *data_location;
    void *load_location;

    int size, node, extra_space, extra_space_size, rc;


    // Get the information that describe where our information is located...
    rc = get_subcomponent_information(image, path, &load_location,
        &data_location, &size, &node);

    if(rc != SUCCESS)
        return NULL;

    // And query for how much extra space we should add to the FDT,
    // to allow the FDT to grow, so we can add new paramters.
    extra_space_location = fdt_getprop(image, node, "extra-space", &extra_space_size);
    if(extra_space_size <= 0) {
        printf("ERROR: Couldn't determine how much extra space to grant FDT! (%d)", extra_space_size);
        return NULL;
    }

    // Retrieve the load location.
    extra_space = __read_extra_space_from_fdt(extra_space_location);
    size       += extra_space;
    printf("  image requests extra space:            %d bytes\n", extra_space);
    printf("  growing device tree to:                %d bytes\n", size);
    printf("  expanded image will end at:            0x%p", load_location + size);

    // Load the FDT into its new location, converting it if necessary,
    // and expanding it to fill the free space for future modifications.
    fdt_open_into(data_location, load_location, size);
    printf("  device tree instantiated of size:      %d bytes\n", fdt_totalsize(load_location));

    return load_location;
}


/**
 * Adjust the target FDT's memory to match the memory regions provided by the bootloader.
 * This accounts for any memory set aside by the bootloader, e.g. for the secure world.
 * See the caveat in update_fdt_for_xen.
 *
 * @param fdt The FDT to be updated.
 *
 * @return SUCCESS, or an error code on failure
 */
int update_fdt_memory(void *target_fdt, void *source_fdt)
{
    const struct fdt_property *source_reg;

    int target_memory_node, source_memory_node, rc;
    int root_node = find_node(target_fdt, "/");

    // Ensure that we /have/ a root node.
    if(root_node < 0) {
        printf("ERROR: Could not find the required root node in the target FDT (%s)!\n", fdt_strerror(root_node));
        return root_node;
    }

    // Create a memory node in the target FDT.
    target_memory_node = fdt_add_subnode(target_fdt, root_node, "memory");

    // If the node already exists, we'll use it in-place.
    if(target_memory_node == -FDT_ERR_EXISTS) {
      target_memory_node = find_node(target_fdt, "/memory");
    }

    // If we weren't able to resolve the memory node, fail out.
    if(target_memory_node < 0) {
        printf("ERROR: Could not add the memory subnode to the target FDT (%s)!\n", fdt_strerror(target_memory_node));
        return target_memory_node;
    }

    // Find the memory node in the source FDT-- this contains the source memory information.
    source_memory_node = fdt_path_offset(source_fdt, "/memory");
    if(source_memory_node < 0) {
        printf("ERROR: Could not retreive memory topology from the bootloader! (%s)!\n", fdt_strerror(source_memory_node));
        return source_memory_node;
    }

    // Retreive the property that contains the bootloader-provided memory topology.
    source_reg = fdt_get_property(source_fdt, source_memory_node, "reg", NULL);
    if(!source_reg)
    {
        printf("ERROR: Could not process the bootloader-provided memory topology!\n");
        return -FDT_ERR_BADVALUE;
    }

    // Copy the memory topology over to the target FDT. For now, we assume the cell sizes
    // (address and size) match the target, as discharge does.
    rc = fdt_setprop(target_fdt, target_memory_node, "reg", source_reg->data, fdt32_to_cpu(source_reg->len));
    if(rc != SUCCESS)
    {
        printf("ERROR: Could not update the target memory topology (%s)!\n", fdt_strerror(rc));
        return rc;
    }

    return SUCCESS;
}


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
    const char *compatible, const char *module_node_name)
{
    int module_node, rc;
    int root_node = find_node(fdt, "/");

    // If we couldn't find the root node, something's horribly wrong.
    if(root_node < 0) {
        printf("ERROR: Could not find the required root node in the target FDT (%d)!\n", root_node);
        return root_node;
    }

    // Create a module node for Xen's representation of the module.
    // We skip the first character, which should be a leading slash.
    module_node = fdt_add_subnode(fdt, root_node, &module_node_name[1]);

    // If the module already exists, we'll use it in-place.
    if(module_node == -FDT_ERR_EXISTS) {
      module_node = find_node(fdt, module_node_name);
    }

    // If we weren't able to resolve the module node, fail out.
    if(module_node < 0) {
        printf("ERROR: Could not add the %s subnode to the target FDT (%s)!\n", compatible, fdt_strerror(module_node));
        return module_node;
    }

    // Set the new module's compatible.
    rc = fdt_setprop_string(fdt, module_node, "compatible", compatible);
    if(rc != SUCCESS) {
        printf("ERROR: Could not set up the %s node identifier! (%d)\n", compatible, rc);
        return rc;
    }


    // And indicate that this is a module.
    rc = fdt_appendprop_string(fdt, module_node, "compatible", "multiboot,module");
    if(rc != SUCCESS) {
        printf("ERROR: Could not set up the %s node identifier! (%d)\n", compatible, rc);
        return rc;
    }

    // Add the kernel's location...
    rc = fdt_setprop_u64(fdt, module_node, "reg", (uint64_t)module);
    if(rc != SUCCESS) {
        printf("ERROR: Could not add a %s module's location to the node! (%d)\n", compatible, rc);
        return rc;
    }

    // ... and add its size.
    rc = fdt_appendprop_u64(fdt, module_node, "reg", (uint64_t)size);
    if(rc != SUCCESS) {
        printf("ERROR: Could not add the %s module's size to the node! (%d)\n", compatible, rc);
        return rc;
    }

    // If all of these steps succeeded, we're ready to launch the kernel!
    return SUCCESS;
}
