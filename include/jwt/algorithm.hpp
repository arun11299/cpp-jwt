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
                                           const string_view header,
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
    int compare_res = 0;
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


#endif
