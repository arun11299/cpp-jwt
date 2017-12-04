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
