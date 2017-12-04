#ifndef JWT_HPP
#define JWT_HPP

#include <set>
#include <array>
#include <string>
#include <chrono>
#include <ostream>
#include <cassert>
#include <cstring>

#include "jwt/base64.hpp"
#include "jwt/algorithm.hpp"
#include "jwt/string_view.hpp"
#include "jwt/parameters.hpp"
#include "jwt/exceptions.hpp"
#include "jwt/json/json.hpp"

// For convenience
using json_t = nlohmann::json;
using system_time_t = std::chrono::time_point<std::chrono::system_clock>;

namespace jwt {

/*!
 */
enum class type
{
  JWT = 0,
};

/*!
 */
enum type str_to_type(const string_view typ) noexcept
{
  assert (typ.length() && "Empty type string");

  if (!strcasecmp(typ.data(), "jwt")) return type::JWT;

  assert (0 && "Code not reached");
}


/*!
 */
string_view type_to_str(enum type typ)
{
  switch (typ) {
    case type::JWT: return "JWT";
    default:        assert (0 && "Unknown type");
  };

  assert (0 && "Code not reached");
}


/*!
 * Registered claim names.
 */
enum class registered_claims
{
  // Expiration Time claim
  expiration = 0,
  // Not Before Time claim
  not_before,
  // Issuer name claim
  issuer,
  // Audience claim
  audience,
  // Issued At Time claim 
  issued_at,
  // Subject claim
  subject,
  // JWT ID claim
  jti,
};


/*!
 */
string_view reg_claims_to_str(enum registered_claims claim) noexcept
{
  switch (claim) {
    case registered_claims::expiration: return "exp";
    case registered_claims::not_before: return "nbf";
    case registered_claims::issuer:     return "iss";
    case registered_claims::audience:   return "aud";
    case registered_claims::issued_at:  return "iat";
    case registered_claims::subject:    return "sub";
    case registered_claims::jti:        return "jti";
    default:                            assert (0 && "Not a registered claim");
  };

  assert (0 && "Code not reached");
}

// Fwd declaration for friend functions to specify the 
// default arguments
// See: https://stackoverflow.com/a/23336823/434233
template <typename T, typename = typename std::enable_if<
            detail::meta::has_create_json_obj_member<T>{}>::type>
std::string to_json_str(const T& obj, bool pretty=false);

template <typename T>
std::ostream& write(std::ostream& os, const T& obj, bool pretty=false);

/*!
 */
struct write_interface
{
  /*!
   */
  template <typename T, typename Cond>
  friend std::string to_json_str(const T& obj, bool pretty);

  /*!
   */
  template <typename T>
  friend std::ostream& write(
      std::ostream& os, const T& obj, bool pretty);

  /*!
   */
  template <typename T, typename Cond>
  friend std::ostream& operator<< (std::ostream& os, const T& obj);
};

/*!
 * Provides the functionality for doing
 * base64 encoding and decoding from the
 * json string.
 */
template <typename Derived>
struct base64_enc_dec
{
  /*!
   * Does URL safe base64 encoding
   */
  std::string base64_encode(bool with_pretty = false) const
  {
    std::string jstr = to_json_str(*static_cast<const Derived*>(this), with_pretty);
    std::string b64_str = jwt::base64_encode(jstr.c_str(), jstr.length());
    // Do the URI safe encoding
    auto new_len = jwt::base64_uri_encode(&b64_str[0], b64_str.length());
    b64_str.resize(new_len);

    return b64_str;
  }

  /*!
   * Does URL safe base64 decoding.
   */
  std::string base64_decode(const string_view encoded_str)
  {
    return jwt::base64_uri_decode(encoded_str.data(), encoded_str.length());
  }

};


/*!
 * JWT Header.
 */
struct jwt_header: write_interface
                 , base64_enc_dec<jwt_header>
{
public: // 'tors
  /*!
   */
  jwt_header() = default;

  /*!
   */
  jwt_header(enum algorithm alg, enum type typ = type::JWT)
    : alg_(alg)
    , typ_(typ)
  {
  }

  /**
   * Construct the header from an encoded string.
   * TODO: Throw an exception in case of error
   */
  jwt_header(const string_view enc_str)
  {
    this->decode(enc_str);
  }

  /// Default Copy and assignment
  jwt_header(const jwt_header&) = default;
  jwt_header& operator=(const jwt_header&) = default;

  ~jwt_header() = default;

public: // Exposed APIs
  /*!
   * NOTE: Any previously saved json dump or the encoding of the
   * header would not be valid after modifying the algorithm.
   */
  void algo(enum algorithm alg) noexcept
  {
    alg_ = alg;
  }

  /**
   */
  void algo(const string_view sv)
  {
    alg_ = str_to_alg(sv.data());
  }

  /*!
   */
  enum algorithm algo() const noexcept
  {
    return alg_;
  }

  /*!
   * NOTE: Any previously saved json dump or the encoding of the
   * header would not be valid after modifying the type.
   */
  void typ(enum type typ) noexcept
  {
    typ_ = typ;
  }

  /*!
   */
  enum type typ() const noexcept
  {
    return typ_;
  }

  /*!
   */
  //TODO: error code ?
  std::string encode(bool pprint = false)
  {
    return base64_encode(pprint);
  }

  /**
   */
  void decode(const string_view enc_str, std::error_code& ec) noexcept;

  /**
   */
  void decode(const string_view enc_str) throw(DecodeError);

  /*!
   */
  json_t create_json_obj() const
  {
    json_t obj = json_t::object();
    //TODO: should be able to do with string_view
    obj["typ"] = type_to_str(typ_).to_string();
    obj["alg"] = alg_to_str(alg_).to_string();

    return obj;
  }

private: // Data members
  /// The Algorithm to use for signature creation
  enum algorithm alg_ = algorithm::NONE;

  /// The type of header
  enum type      typ_ = type::JWT;
};


/*!
 * JWT Payload
 */
struct jwt_payload: write_interface
                  , base64_enc_dec<jwt_payload>
{
public: // 'tors
  /**
   */
  jwt_payload() = default;

  /**
   * Construct the payload from an encoded string.
   * TODO: Throw an exception in case of error.
   */
  jwt_payload(const string_view enc_str)
  {
    this->decode(enc_str);
  }

  /// Default copy and assignment operations
  jwt_payload(const jwt_payload&) = default;
  jwt_payload& operator=(const jwt_payload&) = default;

  ~jwt_payload() = default;

public: // Exposed APIs
  /**
   */
  template <typename T,
            typename=typename std::enable_if_t<
              !std::is_same<system_time_t, std::decay_t<T>>::value>
           >
  bool add_claim(const string_view cname, T&& cvalue, bool overwrite=false)
  {
    // Duplicate claim names not allowed
    // if overwrite flag is set to true.
    auto itr = claim_names_.find(cname);
    if (itr != claim_names_.end() && !overwrite) {
      return false;
    }

    // Add it to the known set of claims
    claim_names_.emplace(cname.data(), cname.length());

    //Add it to the json payload
    payload_[cname.data()] = std::forward<T>(cvalue);

    return true;
  }

  /**
   */
  bool add_claim(const string_view cname, system_time_t tp, bool overwrite=false)
  {
    return add_claim(
        cname,
        std::chrono::duration_cast<
          std::chrono::seconds>(tp.time_since_epoch()).count()
        );
  }

  /**
   */
  bool remove_claim(const string_view cname)
  {
    auto itr = claim_names_.find(cname);
    if (itr == claim_names_.end()) return false;

    claim_names_.erase(itr);
    payload_.erase(cname.data());

    return true;
  }

  /**
   */
  bool has_claim(const std::string& cname) const noexcept
  {
    return claim_names_.count(cname);
  }

  /**
   */
  template <typename T>
  bool has_claim_with_value(const std::string& cname, T&& cvalue) const
  {
    auto itr = claim_names_.find(cname);
    if (itr == claim_names_.end()) return false;

    return (cvalue == payload_[cname]);
  }

  /**
   */
  std::string encode(bool pprint = false)
  {
    return base64_encode(pprint);
  }

  /**
   */
  void decode(const string_view enc_str, std::error_code& ec) noexcept;

  /**
   */
  void decode(const string_view enc_str) throw(DecodeError);

  /**
   */
  const json_t& create_json_obj() const
  {
    return payload_;
  }

private:
  /**
   */
  struct case_compare 
  {
    using is_transparent = std::true_type;

    bool operator()(const std::string& lhs, const std::string& rhs) const
    {
      int ret = strcasecmp(lhs.c_str(), rhs.c_str());
      return (ret < 0);
    }

    bool operator()(const string_view lhs, const string_view rhs) const
    {
      int ret = strcasecmp(lhs.data(), rhs.data());
      return (ret < 0);
    }

    bool operator()(const std::string& lhs, const string_view rhs) const
    {
      int ret = strcasecmp(lhs.data(), rhs.data());
      return (ret < 0);
    }

    bool operator()(const string_view lhs, const std::string& rhs) const
    {
      int ret = strcasecmp(lhs.data(), rhs.data());
      return (ret < 0);
    }
  };

  /// JSON object containing payload
  json_t payload_;
  /// The set of claim names in the payload
  std::set<std::string, case_compare> claim_names_;
};

/*!
 */
struct jwt_signature
{
public: // 'tors
  /// Default constructor
  jwt_signature() = default;

  /*!
   */
  jwt_signature(string_view key)
    : key_(key.data(), key.length())
  {
  }

  /// Default copy and assignment operator
  jwt_signature(const jwt_signature&) = default;
  jwt_signature& operator=(const jwt_signature&) = default;

  ~jwt_signature() = default;

public: // Exposed APIs
  /*!
   */
  std::string encode(const jwt_header& header, 
                     const jwt_payload& payload);

  /*!
   */
  bool verify(const jwt_header& header,
              const string_view hdr_pld_sign,
              const string_view jwt_sign);

private: // Private implementation
  /*!
   */
  sign_func_t get_sign_algorithm_impl(const jwt_header& hdr) const noexcept;

  /*!
   */
  verify_func_t get_verify_algorithm_impl(const jwt_header& hdr) const noexcept;

private: // Data members;

  /// The key for creating the JWS
  std::string key_;
};


/**
 */
class jwt_object
{
public: // 'tors
  /**
   */
  jwt_object() = default;

  /**
   */
  template <typename... Args>
  jwt_object(Args&&... args);

public: // Exposed static APIs
  /**
   */
  static std::array<string_view, 3>
  three_parts(const string_view enc_str);

public: // Exposed APIs
  /**
   */
  jwt_payload& payload() noexcept
  {
    return payload_;
  }

  /**
   */
  const jwt_payload& payload() const noexcept
  {
    return payload_;
  }

  /**
   */
  void payload(const jwt_payload& p)
  {
    payload_ = p;
  }

  /**
   */
  void payload(jwt_payload&& p)
  {
    payload_ = std::move(p);
  }

  /**
   */
  void header(const jwt_header& h)
  {
    header_ = h;
  }

  /**
   */
  void header(jwt_header&& h)
  {
    header_ = std::move(h);
  }

  /**
   */
  jwt_header& header() noexcept
  {
    return header_;
  }

  /**
   */
  const jwt_header& header() const noexcept
  {
    return header_;
  }

  /**
   */
  std::string secret() const
  {
    return secret_;
  }

  /**
   */
  void secret(const string_view sv)
  {
    secret_.assign(sv.data(), sv.length());
  }

  /**
   */
  template <typename T, typename Cond>
  jwt_object& add_claim(const string_view name, T&& value);

  /**
   * Specialization for time points.
   * Eg: Users can set `exp` claim to `chrono::system_clock::now()`.
   */
  jwt_object& add_claim(const string_view name, system_time_t time_point);

  /**
   */
  jwt_object& remove_claim(const string_view name);

  /**
   */
  std::string signature() const;

private: // private APIs
  /**
   */
  template <typename... Args>
  void set_parameters(Args&&... args);

  /**
   */
  template <typename M, typename... Rest>
  void set_parameters(params::detail::payload_param<M>&&, Rest&&...);

  /**
   */
  template <typename... Rest>
  void set_parameters(params::detail::secret_param, Rest&&...);

  /**
   */
  template <typename... Rest>
  void set_parameters(params::detail::algorithm_param, Rest&&...);

  /**
   */
  template <typename M, typename... Rest>
  void set_parameters(params::detail::headers_param<M>&&, Rest&&...);

  /**
   */
  void set_parameters();

private: // Data Members

  /// JWT header section
  jwt_header header_;

  /// JWT payload section
  jwt_payload payload_;

  /// The secret key
  std::string secret_;
};

/**
 */
jwt_object jwt_decode(const string_view encoded_str, const string_view key, bool validate=true);

/**
 */
template <typename... Args>
jwt_object decode(const string_view enc_str, const string_view key, Args&&... args);


} // END namespace jwt


#include "jwt/impl/jwt.ipp"

#endif
