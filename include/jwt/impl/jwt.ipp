#ifndef JWT_IPP
#define JWT_IPP

#include "jwt/detail/meta.hpp"

namespace jwt {

template <typename T>
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

void jwt_header::decode(const string_view enc_str)
{
  std::string json_str = base64_decode(enc_str);
  json_t obj = json_t::parse(std::move(json_str));

  //Look for the algorithm field
  auto alg_itr = obj.find("alg");
  assert (alg_itr != obj.end() && "Algorithm header is missing");
  std::error_code ec;

  alg_ = str_to_alg(alg_itr.value().get<std::string>());

  if (alg_ != algorithm::NONE) {
    auto itr = obj.find("typ");
    if (itr == obj.end()) {
      //TODO: set error code
      return;
    }
    auto typ = itr.value().get<std::string>();
    if (strcasecmp(typ.c_str(), "JWT")) {
      //TODO: set error code
      return;
    }
    typ_ = str_to_type(typ);
  }

  return;
}


void jwt_payload::decode(const string_view enc_str)
{
  std::string json_str = base64_decode(enc_str);
  payload_ = json_t::parse(std::move(json_str));
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
 
  std::string b64hash = base64_encode(res.first.c_str(), res.first.length());
  auto new_len = base64_uri_encode(&b64hash[0], b64hash.length());
  b64hash.resize(new_len);

  jwt_msg = data + '.' + b64hash;

  return jwt_msg;
}

bool jwt_signature::verify(const jwt_header& header,
                           const string_view hdr_pld_sign,
                           const string_view jwt_sign)
{
  //TODO: is bool the right choice ?
  verify_func_t verify_fn = get_verify_algorithm_impl(header);
  verify_fn(key_, hdr_pld_sign, jwt_sign);

  return true;
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

template <typename T>
jwt_payload& jwt_object::add_claim(const std::string& name, T&& value)
{
  payload_.add_claim(name, std::forward<T>(value));
  return payload_;
}

jwt_payload& jwt_object::remove_claim(const std::string& name)
{
  payload_.remove_claim(name);
  return payload_;
}

std::string jwt_object::signature() const
{
  jwt_signature jws{secret_};

  return jws.encode(header_, payload_);
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

  size_t tpos = enc_str.find_first_of('.', spos + 1);

  if (tpos != string_view::npos) {
    result[2] = string_view{&enc_str[tpos + 1], tpos - spos - 1};
  }

  return result;
}


//====================================================================

jwt_object jwt_decode(const string_view encoded_str, const string_view key, bool validate)
{
  //TODO: implement error_code
  jwt_object jobj;

  auto parts = jwt_object::three_parts(encoded_str);

  //throws verification error
  jobj.header(jwt_header{parts[0]});
  //throws verification error
  jobj.payload(jwt_payload{parts[1]});

  jwt_signature jsign{key};

  //length of the encoded header and payload only.
  //Addition of '1' to account for the '.' character.
  auto l = parts[0].length() + 1 + parts[1].length();
  jsign.verify(jobj.header(), encoded_str.substr(0, l), parts[2]);

  return jobj;
}

} // END namespace jwt


#endif
