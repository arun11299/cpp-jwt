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

TEST (DecodeTest, DecodeNoneAlgSign)
{
  using namespace jwt::params;
  const char* enc_str = 
    "eyJhbGciOiJOT05FIiwidHlwIjoiSldUIn0.eyJhdWQiOiJyaWZ0LmlvIiwiZXhwIjoxNTEzODYzMzcxLCJzdWIiOiJub3RoaW5nIG11Y2gifQ.";

  std::error_code ec;
  auto obj = jwt::decode(enc_str, "", algorithms({"none"}), ec, verify(false));
  EXPECT_TRUE (ec);
  EXPECT_EQ (ec.value(), static_cast<int>(jwt::AlgorithmErrc::NoneAlgorithmUsed));

  std::cout << obj.payload() << std::endl;

  EXPECT_FALSE (obj.has_claim("iss"));
  EXPECT_FALSE (obj.has_claim("ISS"));

  EXPECT_TRUE (obj.has_claim("aud"));
  EXPECT_TRUE (obj.has_claim("exp"));

  EXPECT_EQ (obj.payload().get_claim_value<uint64_t>("exp"), 1513863371);
}

TEST (DecodeTest, DecodeWrongAlgo)
{
  using namespace jwt::params;

  const char* enc_str =
    "eyJhbGciOiJOT05FIiwidHlwIjoiSldUIn0.eyJhdWQiOiJyaWZ0LmlvIiwiZXhwIjoxNTEzODYzMzcxLCJzdWIiOiJub3RoaW5nIG11Y2gifQ.";

  std::error_code ec;
  auto obj = jwt::decode(enc_str, "", algorithms({"hs256"}), ec, verify(true));
  EXPECT_TRUE (ec);
  EXPECT_EQ (ec.value(), static_cast<int>(jwt::VerificationErrc::InvalidAlgorithm));
}

TEST (DecodeTest, DecodeInvalidHeader)
{
  using namespace jwt::params;

  const char* enc_str =
    "ehbGciOiJOT05FIiwidHlwIjoiSldUIn0.eyJhdWQiOiJyaWZ0LmlvIiwiZXhwIjoxNTEzODYzMzcxLCJzdWIiOiJub3RoaW5nIG11Y2gifQ.";

  std::error_code ec;
  auto obj = jwt::decode(enc_str, "", algorithms({"hs256"}), ec, verify(true));
  ASSERT_TRUE (ec);
  EXPECT_EQ (ec.value(), static_cast<int>(jwt::DecodeErrc::JsonParseError));

}


int main(int argc, char* argv[]) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
  return 0;
}
