#ifndef CPP_JWT_ALGORITHM_HPP
#define CPP_JWT_ALGORITHM_HPP

#include <cassert>
#include <system_error>

#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/ecdsa.h>
#include <openssl/buffer.h>

#include "jwt/string_view.hpp"

namespace jwt {

/// The result type of the signing function
using sign_result_t = std::pair<std::string, std::error_code>;
/// The result type of verification function
using verify_result_t = std::pair<bool, std::error_code>;
/// The function pointer type of the signing function
using sign_func_t   = sign_result_t (*) (const string_view key, 
                                         const string_view data);
///
using verify_func_t = verify_result_t (*) (const string_view key,
                                           const string_view head,
                                           const string_view jwt_sign);

namespace algo {

//TODO: All these can be done using code generaion.
// NO. NEVER. I hate Macros.
// You can use templates too.
// No. I would rather prefer explicit.
// Ok. You win.

/*!
 */
struct HS256
{
  const EVP_MD* operator()() noexcept
  {
    return EVP_sha256();
  }
};

/*!
 */
struct HS384
{
  const EVP_MD* operator()() noexcept
  {
    return EVP_sha384();
  }
};

/*!
 */
struct HS512
{
  const EVP_MD* operator()() noexcept
  {
    return EVP_sha512();
  }
};

/*!
 */
struct NONE
{
  void operator()() noexcept
  {
    return;
  }
};

/*!
 */
struct RS256
{
  static const int type = EVP_PKEY_RSA;

  const EVP_MD* operator()() noexcept
  {
    return EVP_sha256();
  }
};

/*!
 */
struct RS384
{
  static const int type = EVP_PKEY_RSA;

  const EVP_MD* operator()() noexcept
  {
    return EVP_sha384();
  }
};

/*!
 */
struct RS512
{
  static const int type = EVP_PKEY_RSA;

  const EVP_MD* operator()() noexcept
  {
    return EVP_sha512();
  }
};

/*!
 */
struct ES256
{
  static const int type = EVP_PKEY_EC;

  const EVP_MD* operator()() noexcept
  {
    return EVP_sha256();
  }
};

/*!
 */
struct ES384
{
  static const int type = EVP_PKEY_EC;

  const EVP_MD* operator()() noexcept
  {
    return EVP_sha384();
  }
};

/*!
 */
struct ES512
{
  static const int type = EVP_PKEY_EC;

  const EVP_MD* operator()() noexcept
  {
    return EVP_sha512();
  }
};

} //END Namespace algo


/*!
 * JWT signing algorithm.
 */
enum class algorithm
{
  NONE = 0,
  HS256,
  HS384,
  HS512,
  RS256,
  RS384,
  RS512,
  ES256,
  ES384,
  ES512,
  TERM,
};


/*!
 */
string_view alg_to_str(enum algorithm alg) noexcept
{
  switch (alg) {
    case algorithm::HS256: return "HS256";
    case algorithm::HS384: return "HS384";
    case algorithm::HS512: return "HS512";
    case algorithm::RS256: return "RS256";
    case algorithm::RS384: return "RS384";
    case algorithm::RS512: return "RS512";
    case algorithm::ES256: return "ES256";
    case algorithm::ES384: return "ES384";
    case algorithm::ES512: return "ES512";
    case algorithm::TERM:  return "TERM";
    case algorithm::NONE:  return "NONE";
    default:               assert (0 && "Unknown Algorithm");
  };

  assert (0 && "Code not reached");
}

/*!
 */
enum algorithm str_to_alg(const string_view alg) noexcept
{
  if (!alg.length()) return algorithm::NONE;

  if (!strcasecmp(alg.data(), "none"))  return algorithm::NONE;
  if (!strcasecmp(alg.data(), "hs256")) return algorithm::HS256;
  if (!strcasecmp(alg.data(), "hs384")) return algorithm::HS384;
  if (!strcasecmp(alg.data(), "hs512")) return algorithm::HS512;
  if (!strcasecmp(alg.data(), "rs256")) return algorithm::RS256;
  if (!strcasecmp(alg.data(), "rs384")) return algorithm::RS384;
  if (!strcasecmp(alg.data(), "rs512")) return algorithm::RS512;
  if (!strcasecmp(alg.data(), "es256")) return algorithm::ES256;
  if (!strcasecmp(alg.data(), "es384")) return algorithm::ES384;
  if (!strcasecmp(alg.data(), "es512")) return algorithm::ES512;

  assert (0 && "Code not reached");
}


/*!
 */
template <typename Hasher>
struct HMACSign
{
  /// The type of Hashing algorithm
  using hasher_type = Hasher;

  /*!
   */
  static sign_result_t sign(const string_view key, const string_view data)
  {
    std::string sign;
    sign.resize(EVP_MAX_MD_SIZE);
    std::error_code ec{};

    uint32_t len = 0;

    unsigned char* res = HMAC(Hasher{}(),
                              key.data(),
                              key.length(),
                              reinterpret_cast<const unsigned char*>(data.data()),
                              data.length(),
                              reinterpret_cast<unsigned char*>(&sign[0]),
                              &len);

    if (!res) {
      //TODO: Set the appropriate error code
    }
    sign.resize(len);

    return {std::move(sign), ec};
  }

  /*!
   */
  static verify_result_t 
  verify(const string_view key, const string_view head, const string_view sign);

};

/*!
 */
template <>
struct HMACSign<algo::NONE>
{
  using hasher_type = algo::NONE;

  /*!
   */
  static sign_result_t sign(const string_view key, const string_view data)
  {
    std::string sign;
    std::error_code ec{};

    //TODO: Set the appropriate error code for none
    return {sign, ec};
  }

  /*!
   */
  static verify_result_t
  verify(const string_view key, const string_view head, const string_view sign)
  {
    bool compare_res = 0;
    std::error_code ec{};

    //TODO: Set the appropriate error code for none
    return {compare_res, ec};
  }

};


/*!
 */
template <typename Hasher>
struct PEMSign
{
public:
  /// The type of Hashing algorithm
  using hasher_type = Hasher;

  /*!
   */
  static sign_result_t sign(const string_view key, const string_view data)
  {
    std::error_code ec{};

    static auto evpkey_deletor = [](EVP_PKEY* ptr) {
      if (ptr) EVP_PKEY_free(ptr);
    };

    std::unique_ptr<EVP_PKEY, decltype(evpkey_deletor)>
      pkey{load_key(key), evpkey_deletor};

    if (!pkey) {
      //TODO: set valid error code
      return {std::string{}, ec};
    }

    //TODO: Use stack string here ?
    std::string sign = evp_digest(pkey.get(), data, ec);
    if (ec) {
      //TODO: handle error_code
      return {std::move(sign), ec};
    }

    if (Hasher::type != EVP_PKEY_EC) {
      return {std::move(sign), ec};
    } else {
      sign = public_key_ser(pkey.get(), sign, ec);
    }

    return {std::move(sign), ec};
  }

  /*!
   */
  static verify_result_t
  verify(const string_view key, const string_view head, const string_view sign)
  {
    bool compare_res = 0;
    std::error_code ec{};

    //TODO: Set the appropriate error code for none
    return {compare_res, ec};
  }

private:
  /*!
   */
  static EVP_PKEY* load_key(const string_view key);

  /*!
   */
  static std::string evp_digest(EVP_PKEY* pkey, const string_view data, std::error_code& ec);

  /*!
   */
  static std::string public_key_ser(EVP_PKEY* pkey, string_view sign, std::error_code& ec);
};

} // END namespace jwt

#include "jwt/impl/algorithm.ipp"


#endif
