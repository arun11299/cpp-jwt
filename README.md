<h1 align="center">CPP-JWT</h1>

<div align="center">
  <strong>A C++14 library for JSON Web Tokens(JWT)</strong>
</div>

<br/>

<div align="center">
  <sub>
    A little library built with lots of ❤︎  for working with JWT easier.
    By Arun Muralidharan.
  </sub>
</div>

## Table of Contents
- [What is it ?](#whatisit)
- [Example](#example)
- [API Philosophy](#apiphilosophy)
- [Support](#support)
- [External Dependencies](#externaldependencies)
- [Thanks to...](#thanksto)
- [Installation](#installation)
- [API Categories](#apicategories)
- [Advanced Examples](#advancedexamples)
- [Parameters](#parameters)
- [JWS Verification](#jwsverification)
- [Error Codes & Exceptions](#errorcodeexception)
- [Additional Header Data](#additionalheaderdata)
- [Things for improvement](#improvement)


## What is it ?
For the uninitiated, JSON Web Token(JWT) is a JSON based standard (<a href="https://tools.ietf.org/html/rfc7519">RFC-7519</a>) for creating assertions or access tokens that consists of some claims (encoded within the assertion).
This assertion can be used in some kind of bearer authentication mechanism that the server will provide to clients, and the clients can make use of the provided assertion for accessing resources.

Few good resources on this material which I found useful are:
  - <a href="https://scotch.io/tutorials/the-anatomy-of-a-json-web-token">Anatomy of JWT</a>
  - <a href="https://auth0.com/learn/json-web-tokens/">Learn JWT</a> 
  - <a href="https://tools.ietf.org/html/rfc7519">RFC 7519</a>


## Example
  Lets dive into see a simple example of encoding and decoding in Python. Taking the example of <strong>pyjwt</strong> module from its docs.

  ```python
  >>import jwt
  >>key = 'secret'
  >>
  >>encoded = jwt.encode({'some': 'payload'}, key, algorithm='HS256')
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzb21lIjoicGF5bG9hZCJ9.4twFt5NiznN84AWoo1d7KO1T_yoc0Z6XOpOVswacPZg'
  >>
  >>decoded = jwt.decode(encoded, key, algorithms='HS256')
  {'some': 'payload'}
  ```

  Now, lets look at our C++ code doing the same thing.
  ```cpp
  #include <iostream>
  #include "jwt/jwt.hpp"

  int main() {
    using namespace jwt::params;

    auto key = "secret"; //Secret to use for the algorithm
    //Create JWT object
    jwt::jwt_object obj{algorithm("HS256"), payload({{"some", "payload"}}), secret(key)};

    //Get the encoded string/assertion
    auto enc_str = obj.signature();
    std::cout << enc_str << std::endl;

    //Decode
    auto dec_obj = jwt::decode(enc_str, algorithms({"hs256"}), secret(key));
    std::cout << dec_obj.header() << std::endl;
    std::cout << dec_obj.payload() << std::endl;

    return 0;
  }
  ```

  It outputs:
  ```
  eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzb21lIjoicGF5bG9hZCJ9.4twFt5NiznN84AWoo1d7KO1T_yoc0Z6XOpOVswacPZg
  {"alg":"HS256","typ":"JWT"}
  {"some":"payload"}
  ```

  Almost the same API, except for some ugliness here and there. But close enough!

  Lets take another example in which we will see to add payload claim having type other than string.
  The <code>payload</code> function used in the above example to create <code>jwt_object</code> object can only take strings. For anything else, it will throw a compilation error. 

  For adding claims having values other than string, <code>jwt_object</code> class provides <code>add_claim</code> API. We will also see few other APIs in the next example. Make sure to read the comments :).

  ```cpp
    #include <chrono>
    #include <cassert>
    #include <iostream>
    #include "jwt/jwt.hpp"

    int main() {
      using namespace jwt::params;

      jwt::jwt_object obj{algorithm("hs256"), secret("secret"), payload({{"user", "admin"}})};

      //Use add_claim API to add claim values which are
      // _not_ strings.
      // For eg: `iat` and `exp` claims below.
      // Other claims could have been added in the payload
      // function above as they are just stringy things.
      obj.add_claim("iss", "arun.muralidharan")
         .add_claim("sub", "test")
         .add_claim("id", "a-b-c-d-e-f-1-2-3")
         .add_claim("iat", 1513862371)
         .add_claim("exp", std::chrono::system_clock::now() + std::chrono::seconds{10})
         ;

      //Use `has_claim` to check if the claim exists or not
      assert (obj.has_claim("iss"));
      assert (obj.has_claim("exp"));

      //Use `has_claim_with_value` to check if the claim exists
      //with a specific value or not.
      assert (obj.payload().has_claim_with_value("id", "a-b-c-d-e-f-1-2-3"));
      assert (obj.payload().has_claim_with_value("iat", 1513862371));

      //Remove a claim using `remove_claim` API.
      //Most APIs have an overload which takes enum class type as well
      //It can be used interchangeably with strings.
      obj.remove_claim(jwt::registered_claims::expiration);
      assert (not obj.has_claim("exp"));

      //Using `add_claim` with extra features.
      //Check return status and overwrite
      bool ret = obj.payload().add_claim("sub", "new test", false/*overwrite*/);
      assert (not ret);

      // Overwrite an existing claim
      ret = obj.payload().add_claim("sub", "new test", true/*overwrite*/);
      assert ( ret );

      assert (obj.payload().has_claim_with_value("sub", "new test"));

      return 0;
    }
  ```


