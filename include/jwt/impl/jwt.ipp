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


//====================================================================

void jwt_decode(const string_view encoded_str, const string_view key, bool validate)
{
  //TODO: implement error_code
  size_t fpos = encoded_str.find_first_of('.');
  assert (fpos != string_view::npos);

  string_view head{&encoded_str[0], fpos};
  jwt_header hdr;
  hdr.decode(head);

  size_t spos = encoded_str.find_first_of('.', fpos + 1);
  if (spos == string_view::npos) {
    //TODO: Check for none algorithm
  }
  string_view body{&encoded_str[fpos + 1], spos - fpos - 1};

  //Json objects or claims get set in the decode
  jwt_payload pld;
  pld.decode(body);

  jwt_signature jsign{key};
  jsign.verify(hdr, encoded_str.substr(0, spos), encoded_str);
}

} // END namespace jwt


#endif
