#ifndef CPP_JWT_ALGORITHM_IPP
#define CPP_JWT_ALGORITHM_IPP

#include <iostream>

namespace jwt {

template <typename Hasher>
verify_result_t HMACSign<Hasher>::verify(
    const string_view key,
    const string_view head,
    const string_view jwt_sign)
{
  std::error_code ec{};

  std::cout << "Key: "  << key      << std::endl;
  std::cout << "Head: " << head     << std::endl;
  std::cout << "JWT: "  << jwt_sign << std::endl;

  BIO_uptr b64{BIO_new(BIO_f_base64()), bio_deletor};
  if (!b64) {
    throw MemoryAllocationException("BIO_new failed");
  }

  BIO* bmem = BIO_new(BIO_s_mem());
  if (!bmem) {
    throw MemoryAllocationException("BIO_new failed");
  }

  BIO_push(b64.get(), bmem);
  BIO_set_flags(b64.get(), BIO_FLAGS_BASE64_NO_NL);

  unsigned char enc_buf[EVP_MAX_MD_SIZE];
  uint32_t enc_buf_len = 0;

  unsigned char* res = HMAC(Hasher{}(),
                            key.data(),
                            key.length(),
                            reinterpret_cast<const unsigned char*>(head.data()),
                            head.length(),
                            enc_buf,
                            &enc_buf_len);
  if (!res) {
    ec = AlgorithmErrc::VerificationErr;
    return {false, ec};
  }

  BIO_write(b64.get(), enc_buf, enc_buf_len);
  (void)BIO_flush(b64.get());

  int len = BIO_pending(bmem);
  if (len < 0) {
    ec = AlgorithmErrc::VerificationErr;
    return {false, ec};
  }

  std::string cbuf;
  cbuf.resize(len + 1);

  len = BIO_read(bmem, &cbuf[0], len);
  cbuf.resize(len);

  //Make the base64 string url safe
  auto new_len = jwt::base64_uri_encode(&cbuf[0], cbuf.length());
  cbuf.resize(new_len);
  std::cout << "cbuf: " << cbuf << std::endl;

  bool ret = (string_view{cbuf} == jwt_sign);

  return { ret, ec };
}


template <typename Hasher>
verify_result_t PEMSign<Hasher>::verify(
    const string_view key,
    const string_view head,
    const string_view jwt_sign)
{
  std::error_code ec{};
  std::string dec_sig = base64_uri_decode(jwt_sign.data(), jwt_sign.length());

  BIO_uptr bufkey{
      BIO_new_mem_buf((void*)key.data(), key.length()),
      bio_deletor};

  if (!bufkey) {
    throw MemoryAllocationException("BIO_new_mem_buf failed");
  }

  EC_PKEY_uptr pkey{
    PEM_read_bio_PUBKEY(bufkey.get(), nullptr, nullptr, nullptr),
    ev_pkey_deletor};

  if (!pkey) {
    ec = AlgorithmErrc::VerificationErr;
    return { false, ec };
  }

  int pkey_type = EVP_PKEY_id(pkey.get());

  if (pkey_type != Hasher::type) {
    ec = AlgorithmErrc::VerificationErr;
    return { false, ec };
  }

  //Convert EC signature back to ASN1
  if (Hasher::type == EVP_PKEY_EC) {
    EC_SIG_uptr ec_sig{ECDSA_SIG_new(), ec_sig_deletor};
    if (!ec_sig) {
      throw MemoryAllocationException("ECDSA_SIG_new failed");
    }

    //Get the actual ec_key
    EC_KEY_uptr ec_key{EVP_PKEY_get1_EC_KEY(pkey.get()), ec_key_deletor};
    if (!ec_key) {
      throw MemoryAllocationException("EVP_PKEY_get1_EC_KEY failed");
    }

    unsigned int degree = EC_GROUP_get_degree(
        EC_KEY_get0_group(ec_key.get()));
    
    unsigned int bn_len = (degree + 7) / 8;

    if ((bn_len * 2) != dec_sig.length()) {
      ec = AlgorithmErrc::VerificationErr;
      return { false, ec };
    }

    BIGNUM* ec_sig_r = BN_bin2bn((unsigned char*)dec_sig.data(), bn_len, nullptr);
    BIGNUM* ec_sig_s = BN_bin2bn((unsigned char*)dec_sig.data() + bn_len, bn_len, nullptr);

    if (!ec_sig_r || !ec_sig_s) {
      ec = AlgorithmErrc::VerificationErr;
      return { false, ec };
    }

    ECDSA_SIG_set0(ec_sig.get(), ec_sig_r, ec_sig_s);

    size_t nlen = i2d_ECDSA_SIG(ec_sig.get(), nullptr);
    dec_sig.resize(nlen);

    auto data = reinterpret_cast<unsigned char*>(&dec_sig[0]);
    nlen = i2d_ECDSA_SIG(ec_sig.get(), &data);

    if (nlen == 0) {
      ec = AlgorithmErrc::VerificationErr;
      return { false, ec };
    }
  }

  EVP_MDCTX_uptr mdctx_ptr{EVP_MD_CTX_create(), evp_md_ctx_deletor};
  if (!mdctx_ptr) {
    throw MemoryAllocationException("EVP_MD_CTX_create failed");
  }

  if (EVP_DigestVerifyInit(
        mdctx_ptr.get(), nullptr, Hasher{}(), nullptr, pkey.get()) != 1) {
    ec = AlgorithmErrc::VerificationErr;
    return { false, ec };
  }

  if (EVP_DigestVerifyUpdate(mdctx_ptr.get(), head.data(), head.length()) != 1) {
    ec = AlgorithmErrc::VerificationErr;
    return { false, ec };
  }

  if (EVP_DigestVerifyFinal(
        mdctx_ptr.get(), (unsigned char*)&dec_sig[0], dec_sig.length()) != 1) {
    ec = AlgorithmErrc::VerificationErr;
    return { false, ec };
  }

  return { true, ec };
}

///////////////////////

#define SIGN_ERROR(__err) ({ ret = __err; goto jwt_sign_sha_pem_done; })

template <typename Hasher>
void PEMSign<Hasher>::libjwt_sign(char** out, unsigned int *len, const char* str, const char* key, size_t klen)
{
        ECDSA_SIG *ec_sig = NULL;
        const BIGNUM *ec_sig_r = NULL;
        const BIGNUM *ec_sig_s = NULL;
        const EVP_MD *alg;
        int type;
        EVP_PKEY *pkey = NULL;
        int pkey_type;
        unsigned char *sig;
        int ret = 0;
        size_t slen;

        alg = EVP_sha256();
        type = EVP_PKEY_EC;

        BIO_uptr bufkey{
          BIO_new_mem_buf(key, klen),
          bio_deletor};

        if (!bufkey) {
          throw MemoryAllocationException("BIO_new_mem_buf failed");
        }

        pkey = PEM_read_bio_PrivateKey(bufkey.get(), NULL, NULL, NULL);
        if (!pkey) {
          return;
        }

        pkey_type = EVP_PKEY_id(pkey);
        if (pkey_type != type) {
          return;
        }

        EVP_MDCTX_uptr mdctx{EVP_MD_CTX_create(), evp_md_ctx_deletor};
        if (!mdctx) return;

        EVP_DigestSignInit(mdctx.get(), NULL, alg, NULL, pkey);
        EVP_DigestSignUpdate(mdctx.get(), str, strlen(str));
        EVP_DigestSignFinal(mdctx.get(), NULL, &slen);

        sig = (unsigned char*)alloca(slen);

        EVP_DigestSignFinal(mdctx.get(), sig, &slen);


        if (pkey_type != EVP_PKEY_EC) {
                *out = (char*)malloc(slen);
                if (*out == NULL)
                        SIGN_ERROR(ENOMEM);

                memcpy(*out, sig, slen);
                *len = slen;
        } else {
                unsigned int degree, bn_len, r_len, s_len, buf_len;
                unsigned char *raw_buf;
                EC_KEY *ec_key;

                /* For EC we need to convert to a raw format of R/S. */

                /* Get the actual ec_key */
                ec_key = EVP_PKEY_get1_EC_KEY(pkey);
                if (ec_key == NULL)
                        SIGN_ERROR(ENOMEM);

                degree = EC_GROUP_get_degree(EC_KEY_get0_group(ec_key));

                EC_KEY_free(ec_key);

                std::cout << "AAA: " << sig << std::endl;

                /* Get the sig from the DER encoded version. */
                ec_sig = d2i_ECDSA_SIG(NULL, (const unsigned char **)&sig, slen);
                if (ec_sig == NULL)
                        SIGN_ERROR(ENOMEM);

                std::cout << "ON YOUR FACE!!" << std::endl;

                ECDSA_SIG_get0(ec_sig, &ec_sig_r, &ec_sig_s);

                r_len = BN_num_bytes(ec_sig_r);
                s_len = BN_num_bytes(ec_sig_s);
                bn_len = (degree + 7) / 8;
                if ((r_len > bn_len) || (s_len > bn_len))
                        SIGN_ERROR(EINVAL);

                buf_len = 2 * bn_len;
                raw_buf = (unsigned char*)alloca(buf_len);
                if (raw_buf == NULL)
                        SIGN_ERROR(ENOMEM);

                /* Pad the bignums with leading zeroes. */
                memset(raw_buf, 0, buf_len);
                BN_bn2bin(ec_sig_r, raw_buf + bn_len - r_len);
                BN_bn2bin(ec_sig_s, raw_buf + buf_len - s_len);

                *out = (char*)malloc(buf_len);
                if (*out == NULL)
                        SIGN_ERROR(ENOMEM);
                memcpy(*out, raw_buf, buf_len);
                *len = buf_len;
        }

jwt_sign_sha_pem_done:
        if (pkey)
                EVP_PKEY_free(pkey);
        if (ec_sig)
                ECDSA_SIG_free(ec_sig);

        return;
}

//////////////////////

template <typename Hasher>
EVP_PKEY* PEMSign<Hasher>::load_key(
    const string_view key,
    std::error_code& ec)
{
  ec.clear();

  BIO_uptr bio_ptr{
      BIO_new_mem_buf((void*)key.data(), key.length()), 
      bio_deletor};

  if (!bio_ptr) {
    throw MemoryAllocationException("BIO_new_mem_buf failed");
  }

  EVP_PKEY* pkey = PEM_read_bio_PrivateKey(
      bio_ptr.get(), nullptr, nullptr, nullptr);

  if (!pkey) {
    ec = AlgorithmErrc::SigningErr;
    return nullptr;
  }

  auto pkey_type = EVP_PKEY_id(pkey);
  if (pkey_type != Hasher::type) {
    ec = AlgorithmErrc::SigningErr;
    return nullptr;
  }

  return pkey;
}

template <typename Hasher>
std::string PEMSign<Hasher>::evp_digest(
    EVP_PKEY* pkey, 
    const string_view data, 
    std::error_code& ec)
{
  ec.clear();

  EVP_MDCTX_uptr mdctx_ptr{EVP_MD_CTX_create(), evp_md_ctx_deletor};
  std::cout << data << std::endl;
  std::cout << data.length() << std::endl;

  if (!mdctx_ptr) {
    throw MemoryAllocationException("EVP_MD_CTX_create failed");
  }

  //Initialiaze the digest algorithm
  if (EVP_DigestSignInit(
        mdctx_ptr.get(), nullptr, Hasher{}(), nullptr, pkey) != 1) {
    ec = AlgorithmErrc::SigningErr;
    return {};
  }

  //Update the digest with the input data
  if (EVP_DigestSignUpdate(mdctx_ptr.get(), data.data(), data.length()) != 1) {
    ec = AlgorithmErrc::SigningErr;
    return {};
  }

  unsigned long len = 0;

  if (EVP_DigestSignFinal(mdctx_ptr.get(), nullptr, &len) != 1) {
    ec = AlgorithmErrc::SigningErr;
    return {};
  }

  std::string sign;
  sign.resize(len);

  //Get the signature
  if (EVP_DigestSignFinal(mdctx_ptr.get(), (unsigned char*)&sign[0], &len) != 1) {
    ec = AlgorithmErrc::SigningErr;
    return {};
  }

  return sign;
}

template <typename Hasher>
std::string PEMSign<Hasher>::public_key_ser(
    EVP_PKEY* pkey, 
    string_view sign, 
    std::error_code& ec)
{
  // Get the EC_KEY representing a public key and
  // (optionaly) an associated private key
  std::string new_sign;
  ec.clear();

  EC_KEY_uptr ec_key{EVP_PKEY_get1_EC_KEY(pkey), ec_key_deletor};

  if (!ec_key) {
    ec = AlgorithmErrc::SigningErr;
    return {};
  }

  uint32_t degree = EC_GROUP_get_degree(EC_KEY_get0_group(ec_key.get()));

  ec_key.reset(nullptr);

  auto char_ptr = &sign[0];

  std::cout << "AAA: " << char_ptr << std::endl;

  EC_SIG_uptr ec_sig{d2i_ECDSA_SIG(nullptr,
                                   (const unsigned char**)&char_ptr,
                                   sign.length()),
                     ec_sig_deletor};

  if (!ec_sig) {
    ec = AlgorithmErrc::SigningErr;
    std::cout << "1\n";
    return {};
  }

  const BIGNUM* ec_sig_r = nullptr;
  const BIGNUM* ec_sig_s = nullptr;

  ECDSA_SIG_get0(ec_sig.get(), &ec_sig_r, &ec_sig_s);

  auto r_len = BN_num_bytes(ec_sig_r);
  auto s_len = BN_num_bytes(ec_sig_s);
  auto bn_len = (degree + 7) / 8;

  if ((r_len > bn_len) || (s_len > bn_len)) {
    ec = AlgorithmErrc::SigningErr;
    std::cout << "2\n";
    return {};
  }

  auto buf_len = 2 * bn_len;
  new_sign.resize(buf_len);

  BN_bn2bin(ec_sig_r, (unsigned char*)&new_sign[0] + bn_len - r_len);
  BN_bn2bin(ec_sig_s, (unsigned char*)&new_sign[0] + buf_len - s_len);

  return new_sign;
}

} // END namespace jwt

#endif
