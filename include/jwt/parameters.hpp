#ifndef CPP_JWT_PARAMETERS_HPP
#define CPP_JWT_PARAMETERS_HPP

#include <map>
#include <utility>
#include <unordered_map>

#include "jwt/detail/meta.hpp"
#include "jwt/string_view.hpp"

namespace jwt {
namespace params {


namespace detail {
/**
 * Parameter for providing the payload.
 * Takes a Mapping concept representing
 * key-value pairs.
 *
 * NOTE: MappingConcept allows only strings
 * for both keys and values. Use `add_header`
 * API of `jwt_object` otherwise.
 *
 * Modeled as ParameterConcept.
 */
template <typename MappingConcept>
struct payload_param
{
  payload_param(MappingConcept&& mc)
    : payload_(std::forward<MappingConcept>(mc))
  {}

  MappingConcept get() && { return std::move(payload_); }
  const MappingConcept& get() const& { return payload_; }

  MappingConcept payload_;
};

/**
 * Parameter for providing the secret key.
 * Stores only the view of the provided string
 * as string_view. Later the implementation may or
 * may-not copy it.
 *
 * Modeled as ParameterConcept.
 */
struct secret_param
{
  secret_param(string_view sv)
    : secret_(sv)
  {}

  string_view get() { return secret_; }
  string_view secret_;
};

/**
 * Parameter for providing additional headers.
 * Takes a mapping concept representing
 * key-value pairs.
 *
 * Modeled as ParameterConcept.
 */
template <typename MappingConcept>
struct headers_param
{
  headers_param(MappingConcept&& mc)
    : headers_(std::forward<MappingConcept>(mc))
  {}

  MappingConcept get() && { return std::move(headers_); }
  const MappingConcept& get() const& { return headers_; }

  MappingConcept headers_;
};

} // END namespace detail

// Useful typedef
using param_init_list_t = std::initializer_list<std::pair<jwt::string_view, jwt::string_view>>;


/**
 */
template <typename MappingConcept,
          typename=typename jwt::detail::meta::is_mapping_concept<MappingConcept>::type>
detail::payload_param<MappingConcept> 
payload(MappingConcept&& mc)
{
  return { std::forward<MappingConcept>(mc) };
}

/**
 */
detail::payload_param<std::unordered_map<std::string, std::string>>
payload(const param_init_list_t& kvs)
{
  std::unordered_map<std::string, std::string> m;

  for (const auto& elem : kvs) {
    m.emplace(elem.first.data(), elem.second.data());
  }

  return { std::move(m) };
}


/**
 */
detail::secret_param secret(string_view sv)
{
  return { sv };
}

/**
 */
template <typename MappingConcept,
          typename=typename jwt::detail::meta::is_mapping_concept<MappingConcept>::type>
detail::headers_param<MappingConcept>
headers(MappingConcept&& mc)
{
  return { std::forward<MappingConcept>(mc) };
}

/**
 */
  detail::headers_param<std::map<std::string, std::string>>
headers(const param_init_list_t& kvs)
{
  std::map<std::string, std::string> m;

  for (const auto& elem : kvs) {
    m.emplace(elem.first.data(), elem.second.data());
  }

  return { std::move(m) };
}

} // END namespace params
} // END namespace jwt

#endif
