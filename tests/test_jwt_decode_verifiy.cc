#include <iostream>
#include <chrono>
#include <ctime>

#include "jwt/jwt.hpp"
#include "gtest/gtest.h"

TEST (DecodeVerify, BeforeExpiryTest)
{
  using namespace jwt::params;

  jwt::jwt_object obj{algorithm("hs256"), secret("secret")};
  obj.add_claim("iss", "arun.muralidharan")
     .add_claim("exp", std::chrono::system_clock::now() + std::chrono::seconds{10})
     ;

  std::error_code ec;
  auto enc_str = obj.signature(ec);

  ASSERT_FALSE (ec);

  auto dec_obj = jwt::decode(enc_str, algorithms({"hs256"}), ec, secret("secret"), verify(true));
  ASSERT_FALSE (ec);
}

TEST (DecodeVerify, AfterExpiryTest)
{
  using namespace jwt::params;

  jwt::jwt_object obj{algorithm("hs256"), secret("secret")};
  obj.add_claim("iss", "arun.muralidharan")
     .add_claim("exp", std::chrono::system_clock::now() - std::chrono::seconds{1})
     ;

  std::error_code ec;
  auto enc_str = obj.signature(ec);
  ASSERT_FALSE (ec);

  auto dec_obj = jwt::decode(enc_str, algorithms({"hs256"}), ec, secret("secret"), verify(true));
  ASSERT_TRUE (ec);
  EXPECT_EQ (ec.value(), static_cast<int>(jwt::VerificationErrc::TokenExpired));
}

TEST (DecodeVerify, AfterExpiryWithLeeway)
{
  using namespace jwt::params;

  jwt::jwt_object obj{algorithm("hs256"), secret("secret")};
  obj.add_claim("iss", "arun.muralidharan")
     .add_claim("exp", std::chrono::system_clock::now() - std::chrono::seconds{1})
     ;

  std::error_code ec;
  auto enc_str = obj.signature(ec);
  ASSERT_FALSE (ec);

  auto dec_obj = jwt::decode(enc_str, algorithms({"hs256"}), ec, secret("secret"), verify(true), leeway(2));
  ASSERT_FALSE (ec);
}

int main(int argc, char* argv[]) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
