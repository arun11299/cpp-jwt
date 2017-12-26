#include <iostream>
#include "gtest/gtest.h"
#include "jwt/jwt.hpp"

TEST (DecodeTest, InvalidFinalDotForNoneAlg)
{
  using namespace jwt::params;
  const char* inv_enc_str = 
    "eyJhbGciOiJOT05FIiwidHlwIjoiSldUIn0.eyJhdWQiOiJyaWZ0LmlvIiwiZXhwIjoxNTEzODYzMzcxLCJzdWIiOiJub3RoaW5nIG11Y2gifQ";

  std::error_code ec;
  auto obj = jwt::decode(inv_enc_str, "", algorithms({"none", "hs256"}), ec);

  ASSERT_TRUE (ec);
  EXPECT_EQ (ec.value(), static_cast<int>(jwt::DecodeErrc::SignatureFormatError));
}


int main(int argc, char* argv[]) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
  return 0;
}
