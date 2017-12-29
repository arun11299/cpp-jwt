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
