#ifndef JWT_IPP
#define JWT_IPP

#include "jwt/detail/meta.hpp"
#include <algorithm>

namespace jwt {

template <typename T, typename Cond>
std::string to_json_str(const T& obj, bool pretty)
{
  return pretty ? obj.create_json_obj().dump(2)
                : obj.create_json_obj().dump()
                ;
}


template <typename T>
std::ostream& write(std::ostream& os, const T& obj, bool pretty)
{
  pretty ? (os << std::setw(2) << obj.create_json_obj())
         : (os                 << obj.create_json_obj())
         ;

  return os;
}


template <typename T,
          typename = typename std::enable_if<
            detail::meta::has_create_json_obj_member<T>{}>::type>
std::ostream& operator<< (std::ostream& os, const T& obj)
{
  os << obj.create_json_obj();
  return os;
}

//========================================================================

void jwt_header::decode(const string_view enc_str, std::error_code& ec) noexcept
{
  ec.clear();
  std::string json_str = base64_decode(enc_str);
  json_t obj;

  try {
    obj = json_t::parse(std::move(json_str));
  } catch(const std::exception& e) {
    ec = DecodeErrc::JsonParseError;
    return;
  }

  //Look for the algorithm field
  auto alg_itr = obj.find("alg");
  if (alg_itr == obj.end()) {
    ec = DecodeErrc::AlgHeaderMiss;
    return;
  }

  alg_ = str_to_alg(alg_itr.value().get<std::string>());

  if (alg_ != algorithm::NONE)
  {
    auto itr = obj.find("typ");
    if (itr == obj.end()) {
      ec = DecodeErrc::TypHeaderMiss;
      return;
    }

    const auto& typ = itr.value().get<std::string>();
    if (strcasecmp(typ.c_str(), "JWT")) {
      ec = DecodeErrc::TypMismatch;
      return;
    }

    typ_ = str_to_type(typ);
  } else {
    //TODO:
  }

  return;
}

void jwt_header::decode(const string_view enc_str) throw(DecodeError)
{
  std::error_code ec;
  decode(enc_str, ec);
  if (ec) {
    throw DecodeError(ec.message());
  }
  return;
}

void jwt_payload::decode(const string_view enc_str, std::error_code& ec) noexcept
{
  ec.clear();
  std::string json_str = base64_decode(enc_str);
  try {
    payload_ = json_t::parse(std::move(json_str));
  } catch(const std::exception& e) {
    ec = DecodeErrc::JsonParseError;
    return;
  }
  //populate the claims set
  for (auto it = payload_.begin(); it != payload_.end(); ++it) {
    auto ret = claim_names_.insert(it.key());
    if (!ret.second) {
      ec = DecodeErrc::DuplClaims;
      break;
    }
  }

  return;
}

void jwt_payload::decode(const string_view enc_str) throw(DecodeError)
{
  std::error_code ec;
  decode(enc_str, ec);
  if (ec) {
    throw DecodeError(ec.message());
  }
  return;
}

std::string jwt_signature::encode(const jwt_header& header,
                                  const jwt_payload& payload)
{
  std::string jwt_msg;
  //TODO: Optimize allocations

  sign_func_t sign_fn = get_sign_algorithm_impl(header);

  std::string hdr_sign = header.base64_encode();
  std::string pld_sign = payload.base64_encode();

  std::string data = hdr_sign + '.' + pld_sign;
  auto res = sign_fn(key_, data);
  if (res.second) {
    std::cout << res.second.message() << std::endl;
    return {};
  }
 
  std::string b64hash = base64_encode(res.first.c_str(), res.first.length());
  auto new_len = base64_uri_encode(&b64hash[0], b64hash.length());
  b64hash.resize(new_len);

  jwt_msg = data + '.' + b64hash;

  return jwt_msg;
}

verify_result_t jwt_signature::verify(const jwt_header& header,
                           const string_view hdr_pld_sign,
                           const string_view jwt_sign)
{
  verify_func_t verify_fn = get_verify_algorithm_impl(header);
  return verify_fn(key_, hdr_pld_sign, jwt_sign);
}


sign_func_t 
jwt_signature::get_sign_algorithm_impl(const jwt_header& hdr) const noexcept
{
  sign_func_t ret = nullptr;

  switch (hdr.algo()) {
  case algorithm::HS256:
    ret = HMACSign<algo::HS256>::sign;
    break;
  case algorithm::HS384:
    ret = HMACSign<algo::HS384>::sign;
    break;
  case algorithm::HS512:
    ret = HMACSign<algo::HS512>::sign;
    break;
  case algorithm::NONE:
    ret = HMACSign<algo::NONE>::sign;
    break;
  case algorithm::RS256:
    ret = PEMSign<algo::RS256>::sign;
    break;
  case algorithm::RS384:
    ret = PEMSign<algo::RS384>::sign;
    break;
  case algorithm::RS512:
    ret = PEMSign<algo::RS512>::sign;
    break;
  case algorithm::ES256:
    ret = PEMSign<algo::ES256>::sign;
    break;
  case algorithm::ES384:
    ret = PEMSign<algo::ES384>::sign;
    break;
  case algorithm::ES512:
    ret = PEMSign<algo::ES512>::sign;
    break;
  default:
    assert (0 && "Code not reached");
  };

  return ret;
}



verify_func_t 
jwt_signature::get_verify_algorithm_impl(const jwt_header& hdr) const noexcept
{
  verify_func_t ret = nullptr;

  switch (hdr.algo()) {
  case algorithm::HS256:
    ret = HMACSign<algo::HS256>::verify;
    break;
  case algorithm::HS384:
    ret = HMACSign<algo::HS384>::verify;
    break;
  case algorithm::HS512:
    ret = HMACSign<algo::HS512>::verify;
    break;
  case algorithm::NONE:
    ret = HMACSign<algo::NONE>::verify;
    break;
  case algorithm::RS256:
    ret = PEMSign<algo::RS256>::verify;
    break;
  case algorithm::RS384:
    ret = PEMSign<algo::RS384>::verify;
    break;
  case algorithm::RS512:
    ret = PEMSign<algo::RS512>::verify;
    break;
  case algorithm::ES256:
    ret = PEMSign<algo::ES256>::verify;
    break;
  case algorithm::ES384:
    ret = PEMSign<algo::ES384>::verify;
    break;
  case algorithm::ES512:
    ret = PEMSign<algo::ES512>::verify;
    break;
  default:
    assert (0 && "Code not reached");
  };

  return ret;
}


//
template <typename... Args>
jwt_object::jwt_object(Args&&... args)
{
  static_assert (detail::meta::are_all_params<Args...>::value,
      "All constructor argument types must model ParameterConcept");

  set_parameters(std::forward<Args>(args)...);
}

template <typename Map, typename... Rest>
void jwt_object::set_parameters(
    params::detail::payload_param<Map>&& payload, Rest&&... rargs)
{
  for (const auto& elem : payload.get()) {
    payload_.add_claim(std::move(elem.first), std::move(elem.second));
  }
  set_parameters(std::forward<Rest>(rargs)...);
}

template <typename... Rest>
void jwt_object::set_parameters(
    params::detail::secret_param secret, Rest&&... rargs)
{
  secret_.assign(secret.get().data(), secret.get().length());
  set_parameters(std::forward<Rest>(rargs)...);
}

template <typename... Rest>
void jwt_object::set_parameters(
    params::detail::algorithm_param alg, Rest&&... rargs)
{
  header_.algo(alg.get());
  set_parameters(std::forward<Rest>(rargs)...);
}

template <typename Map, typename... Rest>
void jwt_object::set_parameters(
    params::detail::headers_param<Map>&& header, Rest&&... rargs)
{
  //TODO: add kid support
  set_parameters(std::forward<Rest>(rargs)...);
}

void jwt_object::set_parameters()
{
  //setinel call
  return;
}

template <typename T,
          typename=typename std::enable_if_t<
            !std::is_same<system_time_t, std::decay_t<T>>::value>
         >
jwt_object& jwt_object::add_claim(const string_view name, T&& value)
{
  payload_.add_claim(name, std::forward<T>(value));
  return *this;
}

jwt_object& jwt_object::add_claim(const string_view name, system_time_t tp)
{
  return add_claim(
      name,
      std::chrono::duration_cast<
        std::chrono::seconds>(tp.time_since_epoch()).count()
      );
}

jwt_object& jwt_object::remove_claim(const string_view name)
{
  payload_.remove_claim(name);
  return *this;
}

std::string jwt_object::signature() const
{
  jwt_signature jws{secret_};

  return jws.encode(header_, payload_);
}

template <typename Params, typename SequenceT>
std::error_code jwt_object::verify(
    const Params& dparams,
    const params::detail::algorithms_param<SequenceT>& algos) const
{
  std::error_code ec{};

  //Verify if the algorithm set in the header
  //is any of the one expected by the client.
  auto fitr = std::find_if(algos.get().begin(), 
                           algos.get().end(),
                           [&](const auto& elem) 
                           {
                             return jwt::str_to_alg(elem) == header().algo();
                           });

  if (fitr == algos.get().end()) {
    ec = VerificationErrc::InvalidAlgorithm;
    return ec;
  }

  //Check for the expiry timings
  if (has_claim(registered_claims::expiration)) {
    auto curr_time = 
        std::chrono::duration_cast<
                 std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();

    auto p_exp = payload()
                 .get_claim_value<uint64_t>(registered_claims::expiration);

    if (p_exp < (curr_time + dparams.leeway)) {
      ec = VerificationErrc::TokenExpired;
      return ec;
    }
  } 

  //Check for issuer
  if (dparams.has_issuer &&
      has_claim(registered_claims::issuer)) 
  {
    jwt::string_view p_issuer = payload()
                                .get_claim_value<std::string>(registered_claims::issuer);

    if (p_issuer.data() != dparams.issuer) {
      ec = VerificationErrc::InvalidIssuer;
      return ec;
    }
  }

  //Check for audience
  if (dparams.has_aud &&
      has_claim(registered_claims::audience)) 
  {
    jwt::string_view p_aud = payload()
                             .get_claim_value<std::string>(registered_claims::audience);

    if (p_aud.data() != dparams.aud) {
      ec = VerificationErrc::InvalidAudience;
      return ec;
    }
  }

  return ec;
}


std::array<string_view, 3>
jwt_object::three_parts(const string_view enc_str)
{
  std::array<string_view, 3> result;

  size_t fpos = enc_str.find_first_of('.');
  assert (fpos != string_view::npos);

  result[0] = string_view{&enc_str[0], fpos};

  size_t spos = enc_str.find_first_of('.', fpos + 1);
  if (spos == string_view::npos) {
    //TODO: Check for none algorithm
  }

  result[1] = string_view{&enc_str[fpos + 1], spos - fpos - 1};

  if (spos != enc_str.length()) {
    result[2] = string_view{&enc_str[spos + 1], enc_str.length() - spos - 1};
  }

  return result;
}


//====================================================================

namespace { // Anonymous namespace

template <typename DecodeParams, typename... Rest>
void set_decode_params(DecodeParams& dparams, params::detail::leeway_param l, Rest&&... args)
{
  dparams.leeway = l.get();
  set_decode_params(dparams, std::forward<Rest>(args)...);
  return;
}

template <typename DecodeParams, typename... Rest>
void set_decode_params(DecodeParams& dparams, params::detail::verify_param v, Rest&&... args)
{
  dparams.verify = v.get();
  set_decode_params(dparams, std::forward<Rest>(args)...);
  return;
}

template <typename DecodeParams, typename... Rest>
void set_decode_params(DecodeParams& dparams, params::detail::issuer_param i, Rest&&... args)
{
  dparams.issuer = std::move(i).get();
  dparams.has_issuer = true;
  set_decode_params(dparams, std::forward<Rest>(args)...);
  return;
}

template <typename DecodeParams, typename... Rest>
void set_decode_params(DecodeParams& dparams, params::detail::audience_param a, Rest&&... args)
{
  dparams.aud = std::move(a).get();
  dparams.has_aud = true;
  set_decode_params(dparams, std::forward<Rest>(args)...);
}

template <typename DecodeParams>
void set_decode_params(DecodeParams& dparams)
{
  return;
}

} // END anonymous namespace

template <typename SequenceT, typename... Args>
jwt_object decode(const string_view enc_str,
                  const string_view key,
                  const params::detail::algorithms_param<SequenceT>& algos,
                  std::error_code& ec,
                  Args&&... args)
{
  ec.clear();
  jwt_object obj;

  if (algos.get().size() == 0) {
    ec = DecodeErrc::EmptyAlgoList;
    return obj;
  }

  struct decode_params
  {
    /// Verify parameter. Defaulted to true.
    bool verify = true;
    /// Leeway parameter. Defaulted to zero seconds.
    uint32_t leeway = 0;
    ///The issuer
    //TODO: optional type
    bool has_issuer = false;
    std::string issuer;
    ///The audience
    //TODO: optional type
    bool has_aud = false;
    std::string aud;
  };

  decode_params dparams{};
  set_decode_params(dparams, std::forward<Args>(args)...);

  auto parts = jwt_object::three_parts(enc_str);

  //throws decode error
  obj.header(jwt_header{parts[0]});

  //throws decode error
  obj.payload(jwt_payload{parts[1]});

  if (dparams.verify) {
    ec = obj.verify(dparams, algos);

    if (ec) return obj;
  }

  jwt_signature jsign{key};
 
  // Length of the encoded header and payload only.
  // Addition of '1' to account for the '.' character.
  auto l = parts[0].length() + 1 + parts[1].length();

  //MemoryAllocationError is not caught
  verify_result_t res = jsign.verify(obj.header(), enc_str.substr(0, l), parts[2]);
  if (res.second) {
    ec = res.second;
    return obj;
  }

  if (!res.first) {
    ec = VerificationErrc::InvalidSignature;
    return obj;
  }

  return obj; 
}



template <typename SequenceT, typename... Args>
jwt_object decode(const string_view enc_str,
                  const string_view key,
                  const params::detail::algorithms_param<SequenceT>& algos,
                  Args&&... args)
{
  std::error_code ec{};
  auto jwt_obj = decode(enc_str,
                        key,
                        algos,
                        ec,
                        std::forward<Args>(args)...);

  if (ec) {
    jwt_throw_exception(ec);
  }

  return jwt_obj;
}


void jwt_throw_exception(const std::error_code& ec)
{
  const auto& cat = ec.category();

  if (&cat == &theVerificationErrorCategory)
  {
    switch (ec.value()) {
    case VerificationErrc::InvalidAlgorithm:
    {
      throw InvalidAlgorithmError(ec.message());
    }
    case VerificationErrc::TokenExpired:
    {
      throw TokenExpiredError(ec.message());
    }
    case VerificationErrc::InvalidIssuer:
    {
      throw InvalidIssuerError(ec.message());
    }
    case VerificationErrc::InvalidAudience:
    {
      throw InvalidAudienceError(ec.message());
    }
    case VerificationErrc::ImmatureSignature:
    {
      throw ImmatureSignatureError(ec.message());
    }
    case VerificationErrc::InvalidSignature:
    {
      throw InvalidSignatureError(ec.message());
    }
    default:
      assert (0 && "Unknown error code");
    };
  }

  if (&cat == &theDecodeErrorCategory)
  {
    throw DecodeError(ec.message());
  }

  if (&cat == &theAlgorithmErrCategory)
  {
    switch (ec.value()) {
    case AlgorithmErrc::VerificationErr:
      throw InvalidSignatureError(ec.message());
    default:
      assert (0 && "Unknown error code or not to be treated as an error");
    };
  }

  assert (0 && "Unknown error code category");
}

} // END namespace jwt


#endif
