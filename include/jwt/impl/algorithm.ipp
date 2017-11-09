#ifndef CPP_JWT_ALGORITHM_IPP
#define CPP_JWT_ALGORITHM_IPP

namespace jwt {

template <typename Hasher>
verify_result_t HMACSign<Hasher>::verify(
    const string_view key,
    const string_view head,
    const string_view jwt_sign)
{
  std::error_code ec{};
  static auto bio_deletor = [](BIO* ptr) {
    if (ptr) BIO_free_all(ptr);
  };

  using bio_deletor_t = decltype(bio_deletor);
  using BIO_unique_ptr = std::unique_ptr<BIO_unique_ptr, bio_deletor_t>;

  BIO_unique_ptr b64{BIO_new(BIO_f_base64())};
  if (!b64) {
    //TODO: set error code
    return {false, ec};
  }

  BIO* bmem = BIO_new(BIO_s_mem());
  if (!bmem) {
    //TODO: set error code
    return {false, ec};
  }

  BIO_push(b64, bmem);
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

  unsigned char enc_buf[EVP_MAX_MD_SIZE];

  unsigned char* res = HMAC(Hasher{}(),
                            key.data(),
                            key.length(),
                            reinterpret_cast<const unsigned char*>(head.data()),
                            head.length(),
                            enc_buf,
                            &enc_buf_len);

  return {true, ec};
}

template <typename Hasher>
sign_result_t PEMSign<Hasher>::load_key(const string_view key)
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

template <typename Hasher>
std::string PEMSign<Hasher>::evp_digest(
    EVP_PKEY* pkey, 
    const string_view data, 
    std::error_code& ec)
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

template <typename Hasher>
std::string PEMSign<Hasher>::public_key_ser(
    EVP_PKEY* pkey, 
    string_view sign, 
    std::error_code& ec)
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

} // END namespace jwt

#endif
