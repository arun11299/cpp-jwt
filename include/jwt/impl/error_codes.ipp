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

// Create global object for the error categories
const AlgorithmErrCategory theAlgorithmErrCategory {};

}


// Create the AlgorithmErrc error code
std::error_code make_error_code(AlgorithmErrc err)
{
  return { static_cast<int>(err), theAlgorithmErrCategory };
}


} // END namespace jwt

#endif
