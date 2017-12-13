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
class DecodeError final: public std::runtime_error
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
class VerificationError final: public std::runtime_error
{
public:
  /**
   */
  VerificationError(std::string msg)
    : std::runtime_error(std::move(msg))
  {
  }
};

} // END namespace jwt

#endif
