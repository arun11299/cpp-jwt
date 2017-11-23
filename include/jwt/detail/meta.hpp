#ifndef CPP_JWT_META_HPP
#define CPP_JWT_META_HPP

#include <type_traits>
#include "jwt/string_view.hpp"

namespace jwt {
namespace detail {
namespace meta {

/**
 * The famous void_t trick.
 */
template <typename... T>
struct make_void
{
  using type = void;
};

template <typename... T>
using void_t = typename make_void<T...>::type;

/**
 * A type tag representing an empty tag.
 * To be used to represent a `result-not-found`
 * situation.
 */
struct empty_type {};


/**
 */
template <typename T, typename=void>
struct has_create_json_obj_member
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

/**
 * Checks if the type `T` models MappingConcept.
 *
 * Requirements on type `T` for matching the requirements:
 *  a. Must be able to construct jwt::string_view from the
 *     `key_type` of the map.
 *  b. Must be able to construct jwt::string_view from the
 *    `mapped_type` of the map.
 *  c. The type `T` must have an access operator i.e. operator[].
 *  d. The type `T` must have `begin` and `end` member functions
 *     for iteration.
 *
 *  NOTE: Requirements `a` and `b` means that the concept
 *  type can only hold values that are string or constructible
 *  to form a string_view (basically C strings and std::string)
 */
template <typename T, typename=void>
struct is_mapping_concept: std::false_type
{
};

template <typename T>
struct is_mapping_concept<T,
  void_t<
    typename std::enable_if<
      std::is_constructible<jwt::string_view, typename std::remove_reference_t<T>::key_type>::value,
      void
    >::type,

    typename std::enable_if<
      std::is_constructible<jwt::string_view, typename std::remove_reference_t<T>::mapped_type>::value,
      void
    >::type,

    decltype(
      std::declval<T&>().operator[](std::declval<typename std::remove_reference_t<T>::key_type>()),
      std::declval<T&>().begin(),
      std::declval<T&>().end(),
      (void)0
    )
  >
  >: std::true_type
{
};


/**
 * Checks if the type `T` models the ParameterConcept.
 *
 * Requirements on type `T` for matching the requirements:
 *  a. The type must have a `get` method.
 */
template <typename T, typename=void>
struct is_parameter_concept: std::false_type
{
};

template <typename T>
struct is_parameter_concept<T,
  void_t<
    decltype(
      std::declval<T&>().get(),
      (void)0
    )
  >
  >: std::true_type
{
};

/**
 */
template <bool... V>
struct bool_pack {};

/**
 */
template <bool... B>
using all_true = std::is_same<bool_pack<true, B...>, bool_pack<B..., true>>;

/**
 */
template <typename... T>
using are_all_params = all_true<is_parameter_concept<T>{}...>;


} // END namespace meta
} // END namespace detail
} // END namespace jwt

#endif
