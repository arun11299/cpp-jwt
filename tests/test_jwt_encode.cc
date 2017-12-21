#include <iostream>
#include "gtest/gtest.h"
#include "jwt/jwt.hpp"

TEST (EncodeTest, Mytest1)
{
  using namespace jwt::params;

  const std::string expected_sign = 
   "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
   "eyJpYXQiOjE1MTM4NjIzNzEsImlkIjoiYS1iLWMtZC1lLWYtMS0yLTMiLCJpc3MiOiJhcnVuLm11cmFsaWRoYXJhbiIsInN1YiI6ImFkbWluIn0."
   "jk7bRQKTLvs1RcuvMc2B_rt6WBYPoVPirYi_QRBPiuk";

  jwt::jwt_object obj{algorithm("hs256"), secret("secret")};

  obj.add_claim("iss", "arun.muralidharan")
     .add_claim("sub", "admin")
     .add_claim("id", "a-b-c-d-e-f-1-2-3")
     .add_claim("iat", 1513862371)
     ;

  std::cout << "Header: " << obj.header() << std::endl;
  std::cout << "Payload: "<< obj.payload() << std::endl;

  std::string enc_str = obj.signature();

  std::cout << "Signature: " << enc_str << std::endl;

  EXPECT_EQ (enc_str, expected_sign);
}

int main(int argc, char **argv) 
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
