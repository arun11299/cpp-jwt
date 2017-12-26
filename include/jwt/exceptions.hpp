#ifndef CPP_JWT_EXCEPTIONS_HPP
#define CPP_JWT_EXCEPTIONS_HPP

#include <new>
#include <string>

namespace jwt {

/**
 */
class MemoryAllocationException final: public std::bad_alloc
{
public:
  /**
   * Construct MemoryAllocationException from a
   * string literal.
   */
  template <size_t N>
  MemoryAllocationException(const char(&msg)[N])
    : msg_(&msg[0])
  {
  }

  virtual const char* what() const noexcept override
  {
    return msg_;
  }

private:
  const char* msg_ = nullptr;
};

/**
 */
class SigningError : public std::runtime_error
{
public:
  /**
   */
  SigningError(std::string msg)
    : std::runtime_error(std::move(msg))
  {
  }
};

/**
 */
class DecodeError: public std::runtime_error
{
public:
  /**
   */
  DecodeError(std::string msg)
    : std::runtime_error(std::move(msg))
  {
  }
};

/**
 */
class SignatureFormatError final : public DecodeError
{
public:
  /**
   */
  SignatureFormatError(std::string msg)
    : DecodeError(std::move(msg))
  {
  }
};

/**
 */
class KeyNotPresentError final : public DecodeError
{
public:
  /**
   */
  KeyNotPresentError(std::string msg)
    : DecodeError(std::move(msg))
  {
  }
};


/**
 */
class VerificationError : public std::runtime_error
{
public:
  /**
   */
  VerificationError(std::string msg)
    : std::runtime_error(std::move(msg))
  {
  }
};

/**
 */
class InvalidAlgorithmError final: public VerificationError
{
public:
  /**
   */
  InvalidAlgorithmError(std::string msg)
    : VerificationError(std::move(msg))
  {
  }
};

/**
 */
class TokenExpiredError final: public VerificationError
{
public:
  /**
   */
  TokenExpiredError(std::string msg)
    : VerificationError(std::move(msg))
  {
  }
};

/**
 */
class InvalidIssuerError final: public VerificationError
{
public:
  /**
   */
  InvalidIssuerError(std::string msg)
    : VerificationError(std::move(msg))
  {
  }
};

/**
 */
class InvalidAudienceError final: public VerificationError
{
public:
  /**
   */
  InvalidAudienceError(std::string msg)
    : VerificationError(std::move(msg))
  {
  }
};

/**
 */
class ImmatureSignatureError final: public VerificationError
{
public:
  /**
   */
  ImmatureSignatureError(std::string msg)
    : VerificationError(std::move(msg))
  {
  }
};

/**
 */
class InvalidSignatureError final: public VerificationError
{
public:
  /**
   */
  InvalidSignatureError(std::string msg)
    : VerificationError(std::move(msg))
  {
  }
};

} // END namespace jwt

#endif
