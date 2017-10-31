#ifndef JWT_HPP
#define JWT_HPP

namespace jwt {

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


} // END namespace jwt

#endif
