/**
 * Tests for the image-loading components of 
 *
 * Copyright (C) 2016 Assured Information Security, Inc.
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

#include "test_case.h"

extern "C" {
  #include <image.h>
  #include <cache.h>
}

static void * image = NULL;
static size_t image_size = 0;

/**
 * Simple helper that loads the testcase FIT image.
 *
 * @return A pointer to a buffer to the test-case image.
 *    Persistent across all tests, so do not modify the resultant image.
 */
void * get_test_image()
{
    // If we haven't yet fetched the test image, load it.
    if (image == NULL) {
        FILE * fit_file = fopen("assets/image_test.fit", "rb");

        if(!fit_file) {
            FAIL("Could not find test image to work with!");
        }

        // Determine the size of our test image...
        fseek(fit_file, 0, SEEK_END);
        image_size = ftell(fit_file);
        rewind(fit_file);

        // Allocate a buffer that should hold our whole subimage...
        image = malloc(image_size);
        if(!image) {
            FAIL("Could not allocate enough space to run tests!");
            return NULL;
        }

        // ... and read the subimage into it.
        fread(image, image_size, 1, fit_file);
        fclose(fit_file);
    }

    return image;
}

/**
 * Returns the size of the image, in bytes.
 */
size_t get_image_size()
{
    return image_size;
}

SCENARIO("using ensure_image_is_accessible to validate an FDT", "[ensure_image_is_accessible]") {

    WHEN("a valid image is provided") {
        void * image = get_test_image();

        THEN("ensure_image_is_accessible returns SUCCESS") {
            REQUIRE(ensure_image_is_accessible(image) == SUCCESS);
        }

        THEN("ensure_image_is_accessible invalidates all cache lines for the image") {
            MockRepository mocks;
            mocks.ExpectCallFunc(__invalidate_cache_region).With(image, get_image_size());
            ensure_image_is_accessible(image);
        }
    }

    WHEN("an invalid image is provided") {
        int * image = (int *)malloc(1024);
        image[0] = 0xDEADBEEF;

        THEN("ensure_image_is_accessible returns an error code") {
            REQUIRE(ensure_image_is_accessible(image) != SUCCESS);
        }
    }
}
