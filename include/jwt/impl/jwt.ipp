#ifndef JWT_IPP
#define JWT_IPP

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


template <typename T>
std::ostream& operator<< (std::ostream& os, const T& obj)
{
  os << obj.create_json_obj();
  return os;
}

std::string jwt_signature::encode(const jwt_header& header,
                                  const jwt_payload& payload)
{
  std::string jwt_msg;
  //TODO: Optimize allocations

  sign_func_t sign_fn = get_algorithm_impl(header);

  std::string hdr_sign = header.base64_encode();
  std::string pld_sign = payload.base64_encode();

  base64_uri_encode(&hdr_sign[0], hdr_sign.length());
  base64_uri_encode(&pld_sign[0], pld_sign.length());

  std::string data = hdr_sign + '.' + pld_sign;
  auto res = sign_fn(key_, data);
 
  std::string b64hash = base64_encode(res.first.c_str(), res.first.length());
  base64_uri_encode(&b64hash[0], b64hash.length());

  jwt_msg = data + '.' + b64hash;

  return jwt_msg;
}


sign_func_t 
jwt_signature::get_algorithm_impl(const jwt_header& hdr) const noexcept
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

} // END namespace jwt


#endif
