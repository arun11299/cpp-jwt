#ifndef CPP_JWT_META_HPP
#define CPP_JWT_META_HPP

#include <type_traits>

namespace jwt {
namespace detail {
namespace meta {

template <typename... T>
struct make_void
{
  using type = void;
};

template <typename... T>
using void_t = typename make_void<T...>::type;


template <typename T, typename=void>
struct has_create_json_obj_member: std::false_type
{
};

template <typename T>
struct has_create_json_obj_member<T, 
  void_t<
    decltype(
      std::declval<T&&>().create_json_obj(),
      (void)0
    )
  >
  >: std::true_type
{
};


} // END namespace meta
} // END namespace detail
} // END namespace jwt

#endif
