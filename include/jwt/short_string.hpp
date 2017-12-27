/*
Copyright (c) 2017 Arun Muralidharan

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission
 */

#ifndef CPP_JWT_SHORT_STRING_HPP
#define CPP_JWT_SHORT_STRING_HPP

#include <string>
#include "jwt/stack_alloc.hpp"

namespace jwt {
/*
 * A basic_string implementation using stack allocation.
 */
template <size_t N>
using short_string = std::basic_string<char, std::char_traits<char>, stack_alloc<char, N>>;

}

#endif
