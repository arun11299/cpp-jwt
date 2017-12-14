#ifndef CPP_JWT_ERROR_CODES_IPP
#define CPP_JWT_ERROR_CODES_IPP

namespace jwt {
// Anonymous namespace
namespace {

/**
 */
struct AlgorithmErrCategory: std::error_category
{
  const char* name() const noexcept override
  {
    return "algorithms";
  }

  std::string message(int ev) const override
  {
    switch (static_cast<AlgorithmErrc>(ev))
    {
    case AlgorithmErrc::SigningErr:
      return "signing failed";
    case AlgorithmErrc::VerificationErr:
      return "verification failed";
    case AlgorithmErrc::NoneAlgorithmUsed:
      return "none algorithm used";
    };

    assert (0 && "Code not reached");
  }
};

/**
 */
struct DecodeErrorCategory: std::error_category
{
  const char* name() const noexcept override
  {
    return "decode";
  }

  std::string message(int ev) const override
  {
    switch (static_cast<DecodeErrc>(ev))
    {
    case DecodeErrc::AlgHeaderMiss:
      return "missing algorithm header";
    case DecodeErrc::TypHeaderMiss:
      return "missing type header";
    case DecodeErrc::TypMismatch:
      return "type mismatch";
    case DecodeErrc::JsonParseError:
      return "json parse failed";
    case DecodeErrc::DuplClaims:
      return "duplicate claims";
    };

    assert (0 && "Code not reached");
  }
};

// Create global object for the error categories
const AlgorithmErrCategory theAlgorithmErrCategory {};

const DecodeErrorCategory theDecodeErrorCategory {};

}


// Create the AlgorithmErrc error code
std::error_code make_error_code(AlgorithmErrc err)
{
  return { static_cast<int>(err), theAlgorithmErrCategory };
}

std::error_code make_error_code(DecodeErrc err)
{
  return { static_cast<int>(err), theDecodeErrorCategory };
}


} // END namespace jwt

#endif
