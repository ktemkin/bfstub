/**
 * Tests helpers for testing discharge.
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

#include "helpers.h"


/**
 * Creates a new BinaryFile object.
 *
 * @param path The path to the file to be opened.
 */
BinaryFile::BinaryFile(const char * filename)
{
    // Open the provided file.
    std::ifstream file(filename, std::ios::binary | std::ios::ate);

    if(!file) {
        throw std::invalid_argument("Could not open file!");
    }

    // Determine the file's size...
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    // ... and adjust our internal vector so it has enough size
    // for the relevant data.
    this->data.resize(size);

    // Finally, populate the vector with our data.
    file.read(this->data.data(), size);

    if(!file) {
        throw std::runtime_error("Could not read from file!");
    }

}


/**
 * @return The total number of bytes in the file.
 */
size_t BinaryFile::size() {
    return this->data.size();
}

/**
 * A pointer to the raw data content of the file.
 */
void *BinaryFile::raw_bytes() {
    return this->data.data();
}
