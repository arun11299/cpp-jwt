#ifndef CPP_JWT_ERROR_CODES_HPP
#define CPP_JWT_ERROR_CODES_HPP

#include <system_error>

namespace jwt {
/**
 * All the algorithm errors
 */
enum class AlgorithmErrc
{
  SigningErr = 1,
  VerificationErr,
  KeyNotFoundErr,
  NoneAlgorithmUsed, // Not an actual error!
};

/**
 * Algorithm error conditions
 */
enum class AlgorithmFailureSource
{
};

/**
 * Decode error conditions
 */
enum class DecodeErrc
{
  EmptyAlgoList = 1,
  JsonParseError,
  AlgHeaderMiss,
  TypHeaderMiss,
  TypMismatch,
  DuplClaims,
};

/**
 */
enum class VerificationErrc
{
  InvalidAlgorithm = 1,
  TokenExpired,
  InvalidIssuer,
  InvalidAudience,
  ImmatureSignature,
  InvalidSignature,
};

/**
 */
std::error_code make_error_code(AlgorithmErrc err);

/**
 */
std::error_code make_error_code(DecodeErrc err);

/**
 */
std::error_code make_error_code(VerificationErrc err);

} // END namespace jwt


/**
 * Make the custom enum classes as error code
 * adaptable.
 */
namespace std
{
  template <>
  struct is_error_code_enum<jwt::AlgorithmErrc> : true_type {};

  template <>
  struct is_error_code_enum<jwt::DecodeErrc>: true_type {};

  template <>
  struct is_error_code_enum<jwt::VerificationErrc>: true_type {};
}

#include "jwt/impl/error_codes.ipp"

#endif
