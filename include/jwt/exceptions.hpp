#ifndef CPP_JWT_EXCEPTIONS_HPP
#define CPP_JWT_EXCEPTIONS_HPP

#include <new>

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


} // END namespace jwt

#endif
