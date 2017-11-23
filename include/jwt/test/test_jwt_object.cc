#include <iostream>
#include <map>
#include <string>
#include <unordered_map>
#include "jwt/jwt.hpp"

void basic_jwt_object_test()
{
  using namespace jwt::params;
  jwt::jwt_object obj(payload({
                                {"a", "b"},
                                {"c", "d"} 
                              }));

  //check with std::map
  std::map<std::string, std::string> m;
  m["a"] = "b";
  m["c"] = "d";

  jwt::jwt_object obj1{payload(m)};
  
  auto obj2 = std::move(obj1);

  std::cout << obj2.payload() << std::endl;

  //check with unordered map of string_view
  std::unordered_map<jwt::string_view, std::string> um = {
    {"a", "b"},
    {"c", "d"}
  };
  jwt::jwt_object obj3{payload(um)};

  obj3.add_claim("f", true)
      .add_claim("time", 176353563);

  std::cout << jwt::to_json_str(obj3.payload(), true) << std::endl;

  obj3.remove_claim(std::string{"a"});
  std::cout << obj3.payload() << std::endl;

  obj3.secret("secret");
  obj3.header().algo("hs256");

  std::cout << obj3.signature() << std::endl;
}

int main() {
  basic_jwt_object_test();
  return 0;
}
