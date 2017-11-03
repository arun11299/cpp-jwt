#ifndef CPP_JWT_ALGORITHM_HPP
#define CPP_JWT_ALGORITHM_HPP

#include <cassert>
#include <system_error>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/buffer.h>

#include "jwt/string_view.hpp"

namespace jwt {

/// The result type of the signing function
using sign_result_t = std::pair<std::string, std::error_code>;
/// The result type of verification function
using verify_result_t = std::pair<int, std::error_code>;
/// The function pointer type of the signing function
using sign_func_t   = sign_result_t (*) (string_view key, string_view data);

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
 */
template <typename Hasher>
struct HMACSign
{
  /// The type of Hashing algorithm
  using hasher_type = Hasher;

  /*!
   */
  static sign_result_t sign(string_view key, string_view data)
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
  verify(string_view key, string_view head, string_view sign)
  {
    int compare_res = 0;
    std::error_code ec{};

    return {compare_res, ec};
  }

};

/*!
 */
template <>
struct HMACSign<algo::NONE>
{
  using hasher_type = algo::NONE;

  /*!
   */
  static sign_result_t sign(string_view key, string_view data)
  {
    std::string sign;
    std::error_code ec{};

    //TODO: Set the appropriate error code for none
    return {sign, ec};
  }

  /*!
   */
  static verify_result_t
  verify(string_view key, string_view head, string_view sign)
  {
    int compare_res = 0;
    std::error_code ec{};

    //TODO: Set the appropriate error code for none
    return {compare_res, ec};
  }

};


/*!
 */


} // END namespace jwt


#endif
