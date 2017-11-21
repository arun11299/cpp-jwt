#include <iostream>
#include "jwt/jwt.hpp"

void basic_jwt_object_test()
{
  using namespace jwt::params;
  jwt::jwt_object obj(payload({
                                {"a", "b"},
                                {"c", "d"} 
                              }));
}

int main() {
  basic_jwt_object_test();
  return 0;
}
