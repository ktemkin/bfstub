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

#include <vector>
#include <cstdlib>
#include <fstream>

/**
 * Simple class that provides scoped-duration access to a binary file
 * in a C-friendly way. Mostly syntactic sugar.
 */
class BinaryFile {

  public:

      /**
       * Creates a new BinaryFile object.
       *
       * @param path The path to the file to be opened.
       */
      BinaryFile(const char * path);

      /**
       * @return The total number of bytes in the file.
       */
      size_t size();

      /**
       * @return a pointer to the raw data content of the file.
       */
      void *raw_bytes();

      /**
       * @return a pointer to the raw data content of the file.
       */
      operator void*();
      operator char*();

  private:
      std::vector<char> data;
};
