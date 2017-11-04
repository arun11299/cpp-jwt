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
template <typename Hasher>
struct PEMSign
{
public:
  /// The type of Hashing algorithm
  using hasher_type = Hasher;

  /*!
   */
  static sign_result_t sign(string_view key, string_view data)
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
  static EVP_PKEY* load_key(const string_view key)
  {
    auto bio_deletor = [](BIO* ptr) {
      if (ptr) BIO_free(ptr);
    };

    std::unique_ptr<BIO, decltype(bio_deletor)> 
      bio_ptr{BIO_new_mem_buf((void*)key.data(), key.length()), bio_deletor};

    if (!bio_ptr) {
      return nullptr;
    }

    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio_ptr.get(), nullptr, nullptr, nullptr);
    if (!pkey) {
      return nullptr;
    }

    return pkey;
  }

  /*!
   */
  static std::string evp_digest(EVP_PKEY* pkey, const string_view data, std::error_code& ec)
  {
    auto md_deletor = [](EVP_MD_CTX* ptr) {
      if (ptr) EVP_MD_CTX_destroy(ptr);
    };

    std::unique_ptr<EVP_MD_CTX, decltype(md_deletor)>
      mdctx_ptr{EVP_MD_CTX_create(), md_deletor};

    if (!mdctx_ptr) {
      //TODO: set appropriate error_code
      return std::string{};
    }

    //Initialiaze the digest algorithm
    if (EVP_DigestSignInit(
          mdctx_ptr.get(), nullptr, Hasher{}(), nullptr, pkey) != 1) {
      //TODO: set appropriate error_code
      return std::string{};
    }

    //Update the digest with the input data
    if (EVP_DigestSignUpdate(mdctx_ptr.get(), data.data(), data.length()) != 1) {
      //TODO: set appropriate error_code
      return std::string{};
    }

    unsigned long len = 0;

    if (EVP_DigestSignFinal(mdctx_ptr.get(), nullptr, &len) != 1) {
      //TODO: set appropriate error_code
      return std::string{};
    }

    std::string sign;
    sign.resize(len);

    //Get the signature
    if (EVP_DigestSignFinal(mdctx_ptr.get(), (unsigned char*)&sign[0], &len) != 1) {
      //TODO: set appropriate error_code
      return std::string{};
    }

    return sign;
  }


  static std::string public_key_ser(EVP_PKEY* pkey, string_view sign, std::error_code& ec)
  {
    // Get the EC_KEY representing a public key and 
    // (optionaly) an associated private key
    std::string new_sign;

    static auto eckey_deletor = [](EC_KEY* ptr) {
      if (ptr) EC_KEY_free(ptr);
    };

    static auto ecsig_deletor = [](ECDSA_SIG* ptr) {
      if (ptr) ECDSA_SIG_free(ptr);
    };

    std::unique_ptr<EC_KEY, decltype(eckey_deletor)> 
      ec_key{EVP_PKEY_get1_EC_KEY(pkey), eckey_deletor};

    if (!ec_key) {
      //TODO set a valid error code
      return std::string{};
    }

    uint32_t degree = EC_GROUP_get_degree(EC_KEY_get0_group(ec_key.get()));


    std::unique_ptr<ECDSA_SIG, decltype(ecsig_deletor)>
      ec_sig{d2i_ECDSA_SIG(nullptr,
                           (const unsigned char**)&sign[0],
                           sign.length()),
             ecsig_deletor};

    if (!ec_sig) {
      //TODO set a valid error code
      return std::string{};
    }

    const BIGNUM* ec_sig_r = nullptr;
    const BIGNUM* ec_sig_s = nullptr;

#if 1
    //Taken from https://github.com/nginnever/zogminer/issues/39
    auto ECDSA_SIG_get0 = [](const ECDSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps)
    { 
      if (pr != nullptr) *pr = sig->r;
      if (ps != nullptr) *ps = sig->s;
    };
      
#endif

    ECDSA_SIG_get0(ec_sig.get(), &ec_sig_r, &ec_sig_s);

    auto r_len = BN_num_bytes(ec_sig_r);
    auto s_len = BN_num_bytes(ec_sig_s);
    auto bn_len = (degree + 7) / 8;

    if ((r_len > bn_len) || (s_len > bn_len)) {
      //TODO set a valid error code
      return std::string{};
    }

    auto buf_len = 2 * bn_len;
    new_sign.resize(buf_len);

    BN_bn2bin(ec_sig_r, (unsigned char*)&new_sign[0] + bn_len - r_len);
    BN_bn2bin(ec_sig_s, (unsigned char*)&new_sign[0] + buf_len - s_len);

    return new_sign;
  }

};

} // END namespace jwt


#endif
