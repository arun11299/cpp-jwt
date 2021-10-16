<h1 align="center">CPP-JWT</h1>

<div align="center">
  <strong>A C++14 library for JSON Web Tokens(JWT)</strong>
</div>

<br/>

<div align="center">
<img src="http://jwt.io/img/logo-asset.svg" />
</div>

<br/>

<div align="center">
  <sub>
    A little library built with lots of ❤︎  for working with JWT easier.
    By Arun Muralidharan.
  </sub>
</div>

## Table of Contents
- [What is it](#what-is-it)
- [Example](#example)
- [API Philosophy](#api-philosophy)
- [Support](#support)
- [External Dependencies](#external-dependencies)
- [Thanks to...](#thanks-to...)
- [Compiler Support](#compiler-support)
- [Installation](#installation)
- [Parameters](#parameters)
- [Claim Data Types](#claim-data-types)
- [Advanced Examples](#advanced-examples)
- [Error Codes & Exceptions](#error-codes-&-exceptions)
- [Additional Header Data](#additional-header-data)
- [Things for improvement](#things-for-improvement)
- [LICENSE](#license)


## What is it ?
For the uninitiated, JSON Web Token(JWT) is a JSON based standard (<a href="https://tools.ietf.org/html/rfc7519">RFC-7519</a>) for creating assertions or access tokens that consists of some claims (encoded within the assertion).
This assertion can be used in some kind of bearer authentication mechanism that the server will provide to clients, and the clients can make use of the provided assertion for accessing resources.

Few good resources on this material which I found useful are:
  <a href="https://scotch.io/tutorials/the-anatomy-of-a-json-web-token">Anatomy of JWT</a>
  <a href="https://auth0.com/learn/json-web-tokens/">Learn JWT</a>
  <a href="https://tools.ietf.org/html/rfc7519">RFC 7519</a>


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
    auto dec_obj = jwt::decode(enc_str, algorithms({"HS256"}), secret(key));
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

      jwt::jwt_object obj{algorithm("HS256"), secret("secret"), payload({{"user", "admin"}})};

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
      assert (!obj.has_claim("exp"));

      //Using `add_claim` with extra features.
      //Check return status and overwrite
      bool ret = obj.payload().add_claim("sub", "new test", false/*overwrite*/);
      assert (!ret);

      // Overwrite an existing claim
      ret = obj.payload().add_claim("sub", "new test", true/*overwrite*/);
      assert (ret);

      assert (obj.payload().has_claim_with_value("sub", "new test"));

      return 0;
    }
  ```

The <code>jwt_object</code> class is basically a composition of the JWT component classes, which are <code>jwt_header</code> & <code>jwt_payload</code>. For convenience <code>jwt_object</code> exposes only few important APIs to the user, the remaining APIs under <code>jwt_header</code> and <code>jwt_payload</code> can be accessed by calling <code>jwt_object::header()</code> and <code>jwt_object::payload()</code> APIs.


## API Philosophy
I wanted to make the code easy to read and at the same time make most of the standard library and the modern features.
It also uses some metaprogramming tricks to enforce type checks and give better error messages.

The design of `parameters` alleviates the pain of remembering positional arguments. Also makes the APIs more extensible for future enhancements.

The library has 2 sets of APIs for encoding and decoding:
  - API which takes an instance of <code>std::error_code</code>
    These APIs will report the errors by setting the `error_code`. This does not mean that these API would not throw. Memory allocation errors would still be thrown instead of setting the error_code.
  - API which throws exceptions
    All the errors would be thrown as exception.

## Support
<strong>Algorithms and features supported</strong>
- [x] HS256
- [x] HS384
- [x] HS512
- [x] RS256
- [x] RS384
- [x] RS512
- [x] ES256
- [x] ES384
- [x] ES512
- [x] Sign
- [x] Verify
- [x] iss (issuer) check
- [x] sub (subject) check
- [x] aud (audience) check
- [x] exp (expiration time) check
- [x] nbf (not before time) check
- [x] iat (issued at) check
- [x] jti (JWT id) check
- [x] JWS header addition support. For eg "kid" support.

## External Dependencies
  - <strong>OpenSSL </strong>(Version >= 1.0.2j)
    Might work with older version as well, but I did not check that.
  - <strong>Google Test Framework</strong>
    For running the tests
  - <strong>nlohmann JSON library</strong>
    The awesome JSON library :)

## Thanks to...
    - <a href="https://github.com/benmcollins/libjwt">ben-collins JWT library</a>
    - Howard Hinnant for the stack allocator
    - libstd++ code (I took the hashing code for string_view)

## Compiler Support

Tested with <strong>clang-5.0</strong> and <strong>g++-6.4</strong>.
With issue#12, <strong>VS2017</strong> is also supported.

## Building the library

### using conan

```shell
mkdir build
cd build
conan install .. --build missing
cmake ..
cmake --build . -j
```

### using debian

```shell
sudo apt install nlohmann-json3-dev 
sudo apt install libgtest-dev
sudo apt install libssl-dev
mkdir build
cd build
cmake ..
cmake --build . -j
```

## Consuming the library

This library is uses cmake as a build system.
```cmake
# you can use cmake's `find_package` after installation or `add_subdirectory` when vendoring this repository

find_package(cpp-jwt REQUIRED)
# or
add_subdirectory(third_party/cpp-jwt)

add_executable(main main.cpp)
target_link_libraries(main cpp-jwt::cpp-jwt)
```

You can also use this library as a conan package, its available in the [conan center](https://conan.io/center/cpp-jwt):
just add `cpp-jwt[>=1.2]` to your conanfile.txt.

It can also be installed using [vcpkg](https://github.com/microsoft/vcpkg) by adding `"cpp-jwt"` to the dependencies in your `vcpkg.json` file.

## Parameters
There are two sets of parameters which can be used for creating `jwt_object` and for decoding.
All the parameters are basically a function which returns an instance of a type which are modelled after <code>ParameterConcept</code> (see <code>jwt::detail::meta::is_parameter_concept</code>).


- <strong><code>jwt_object</code> creation parameters</strong>
  - <strong>payload</strong>

    Used to populate the claims while creating the `jwt_object` instance.

    There are two overloads of this function:
    - Takes Initializer list of <code>pair<string_view, string_view></code>

      Easy to pass claims with string values which are all known at the time of object creation.
      Can be used like:
      ```cpp
      jwt_object obj {
        payload({
            {"iss", "some-guy"},
            {"sub", "something"},
            {"X-pld", "data1"}
          }),
          ... // Add other parameters
      };
      ```
      Claim values which are not strings/string_views cannot be used.

    - Takes any type which models <code>MappingConcept</code> (see <code>detail::meta::is_mapping_concept</code>)

      This overload can accept <code>std::map</code> or <code>std::unordered_map</code> like containers.
      Can be used like:
      ```cpp
      map<string, string> m;
      m["iss"] = "some-guy";
      m["sub"] = "something";
      m["X-pld"] = "data1";

      jwt_object obj{
        payload(std::move(m)),
        ... // Add other parameters
      };
      //OR
      jwt_object obj{
        payload(m),
        ... // Add other parameters
      };
      ```

  - <strong>secret</strong>

    Used to pass the key which could be some random string or the bytes of the PEM encoded public key
    file in PEM format (wrapped in -----BEGIN PUBLIC KEY----- block) as string.
    The passed string type must be convertible to <code>jwt::string_view</code>

  - <strong>algorithm</strong>

    Used to pass the type of algorithm to use for encoding.
    There are two overloads of this function:
    - Takes <code>jwt::string_view</code>

      Can pass the algorithm value in any case. It is case agnostic.

    - Takes value of type <code>enum class jwt::algorithm</code>

  - <strong>headers</strong>

    Used to populate fields in JWT header. It is very similar to `payload` function parameter.
    There are two overloads for this function which are similar to how <code>payload</code> function is.
    This parameter can be used to add headers other that <strong>alg</strong> and <strong>typ</strong>.

    Same as the case with payload, only string values can be used with this. For adding values of other
    data types, use <code>add_header</code> API of <code>jwt_header</code> class.

    For example adding `kid` header with other additional data fields.
    ```cpp
    jwt_object obj{
      algorithm("HS256"),
      headers({
        {"kid", "12-34-56"},
        {"xtra", "header"}
      })
      ... // Add other parameters
    };
    ```


- <strong>Decoding parameters</strong>

  - <strong>algorithms</strong>

    This is a mandatory parameter which takes a sequence of algorithms (as string) which the user would like to permit when validating the JWT. The value in the header for "alg" would be matched against the provided sequence of values. If nothing matches <code>InvalidAlgorithmError</code> exception or <code>InvalidAlgorithm</code> error would be set based upon the API being used.

    There are two overloads for this function:
    - Takes initializer-list of string values
    - Takes in any type which satifies the <strong>SequenceConcept</strong> (see <code>idetail::meta::is_sequence_concept</code>)

  ```cpp
  jwt::decode(algorithms({"none", "HS256", "RS256"}), ...);

  OR

  std::vector<std::string> algs{"none", "HS256", "RS256"};
  jwt::decode(algorithms(algs), ...);
  ```

  - <strong>secret</strong>

    Optional parameter. To be supplied only when the algorithm used is not "none". Else would throw/set <code>KeyNotPresentError</code> / <code>KeyNotPresent</code> exception/error.

  - <strong>leeway</strong>

    Optional parameter. Used with validation of "Expiration" and "Not Before" claims.
    The value passed should be `seconds` to account for clock skew.
    Default value is `0` seconds.

  - <strong>verify</strong>

    Optional parameter. Suggests if verification of claims should be done or not.
    Takes a boolean value.
    By default verification is turned on.

  - <strong>issuer</strong>

    Optional parameter.
    Takes a string value.
    Validates the passed issuer value against the one present in the decoded JWT object. If the values do not match <code>InvalidIssuerError</code> or <code>InvalidIssuer</code> exception or error_code is thrown/set.

  - <strong>aud</strong>

    Optional parameter.
    Takes a string value.
    Validates the passed audience value against the one present in the decoded JWT object. If the values do not match <code>InvalidAudienceError</code> or <code>InvalidAudience</code> exception or error_code is thrown/set.

  - <strong>sub</strong>

    Optional parameter.
    Takes a string value.
    Validates the passed subject value against the one present in the decoded JWT object. If the values do not match <code>InvalidSubjectError</code> or <code>InvalidSubject</code> exception or error_code is thrown/set.

  - <strong>validate_iat</strong>

    Optional parameter.
    Takes a boolean value.
    Validates the IAT claim. Only checks whether the field is present and is of correct type. If not throws/sets <code>InvalidIATError</code> or <code>InvalidIAT</code>.

    Default value is false.

  - <strong>validate_jti</strong>

    Optional parameter.
    Takes a boolean value.
    Validates the JTI claim. Only checks for the presence of the claim. If  not throws or sets <code>InvalidJTIError</code> or <code>InvalidJTI</code>.

    Default is false.


## Claim Data Types
For the registered claim types the library assumes specific data types for the claim values. Using anything else is not supported and would result in runtime JSON parse error.

    Claim                 |  Data Type
    -----------------------------------
    Expiration(exp)       |  uint64_t (Epoch time in seconds)
    -----------------------------------
    Not Before(nbf)       |  uint64_t (Epoch time in seconds)
    -----------------------------------
    Issuer(iss)           |  string
    -----------------------------------
    Audience(aud)         |  string
    -----------------------------------
    Issued At(iat)        |  uint64_t (Epoch time in seconds)
    -----------------------------------
    Subject(sub)          |  string
    -----------------------------------
    JTI(jti)              | <Value type not checked by library. Upto application.>
    -----------------------------------


## Advanced Examples
We will see few complete examples which makes use of error code checks and exception handling.
The examples are taken from the "tests" section. Users are requested to checkout the tests to find out more ways to use this library.

Expiration verification example (uses error_code):
```cpp
#include <cassert>
#include <iostream>
#include "jwt/jwt.hpp"

int main() {
  using namespace jwt::params;

  jwt::jwt_object obj{algorithm("HS256"), secret("secret")};
  obj.add_claim("iss", "arun.muralidharan")
     .add_claim("exp", std::chrono::system_clock::now() - std::chrono::seconds{1})
     ;

  std::error_code ec;
  auto enc_str = obj.signature(ec);
  assert (!ec);

  auto dec_obj = jwt::decode(enc_str, algorithms({"HS256"}), ec, secret("secret"), verify(true));
  assert (ec);
  assert (ec.value() == static_cast<int>(jwt::VerificationErrc::TokenExpired));

  return 0;
}
```

Expiration verification example (uses exception):
```cpp
#include <cassert>
#include <iostream>
#include "jwt/jwt.hpp"

int main() {
  using namespace jwt::params;

  jwt::jwt_object obj{algorithm("HS256"), secret("secret")};

  obj.add_claim("iss", "arun.muralidharan")
     .add_claim("exp", std::chrono::system_clock::now() - std::chrono::seconds{1})
     ;

  auto enc_str = obj.signature();

  try {
    auto dec_obj = jwt::decode(enc_str, algorithms({"HS256"}), secret("secret"), verify(true));
  } catch (const jwt::TokenExpiredError& e) {
    //Handle Token expired exception here
    //...
  } catch (const jwt::SignatureFormatError& e) {
    //Handle invalid signature format error
    //...
  } catch (const jwt::DecodeError& e) {
    //Handle all kinds of other decode errors
    //...
  } catch (const jwt::VerificationError& e) {
    // Handle the base verification error.
    //NOTE: There are other derived types of verification errors
    // which will be discussed in next topic.
  } catch (...) {
    std::cerr << "Caught unknown exception\n";
  }

  return 0;
}
```

Invalid issuer test(uses error_code):
```cpp
#include <cassert>
#include <iostream>
#include "jwt/jwt.hpp"

int main() {
  using namespace jwt::params;

  jwt::jwt_object obj{algorithm("HS256"), secret("secret"), payload({{"sub", "test"}})};

  std::error_code ec;
  auto enc_str = obj.signature(ec);
  assert (!ec);

  auto dec_obj = jwt::decode(enc_str, algorithms({"HS256"}), ec, secret("secret"), issuer("arun.muralidharan"));
  assert (ec);

  assert (ec.value() == static_cast<int>(jwt::VerificationErrc::InvalidIssuer));

  return 0;
}
```

## Error Codes & Exceptions
The library as we saw earlier supports error reporting via both exceptions and error_code.

<strong>Error codes:</strong>

The error codes are divided into different categories:
- Algorithm Errors

  Used for reporting errors at the time of encoding / signature creation.
  ```cpp
  enum class AlgorithmErrc
  {
    SigningErr = 1,
    VerificationErr,
    KeyNotFoundErr,
    NoneAlgorithmUsed, // Not an actual error!
  };
  ```

  <strong>NOTE:</strong> <code>NoneAlgorithmUsed</code> will be set in the error_code, but it usually should not be treated as a hard error when NONE algorithm is used intentionally.

- Decode Errors

  Used for reporting errors at the time of decoding. Different categories of decode errors are:
  ```cpp
  enum class DecodeErrc
  {
    // No algorithms provided in decode API
    EmptyAlgoList = 1,
    // The JWT signature has incorrect format
    SignatureFormatError,
    // The JSON library failed to parse
    JsonParseError,
    // Algorithm field in header is missing
    AlgHeaderMiss,
    // Type field in header is missing
    TypHeaderMiss,
    // Unexpected type field value
    TypMismatch,
    // Found duplicate claims
    DuplClaims,
    // Key/Secret not passed as decode argument
    KeyNotPresent,
    // Key/secret passed as argument for NONE algorithm.
    // Not a hard error.
    KeyNotRequiredForNoneAlg,
  };
  ```

- Verification errors

  Used for reporting verification errors when the verification falg is set to true in decode API.
  Different categories of decode errors are:
  ```cpp
  enum class VerificationErrc
  {
    //Algorithms provided does not match with header
    InvalidAlgorithm = 1,
    //Token is expired at the time of decoding
    TokenExpired,
    //The issuer specified does not match with payload
    InvalidIssuer,
    //The subject specified does not match with payload
    InvalidSubject,
    //The field IAT is not present or is of invalid type
    InvalidIAT,
    //Checks for the existence of JTI
    //if validate_jti is passed in decode
    InvalidJTI,
    //The audience specified dowes not match with payload
    InvalidAudience,
    //Decoded before nbf time
    ImmatureSignature,
    //Signature match error
    InvalidSignature,
    // Invalid value type used for known claims
    TypeConversionError,
  };
  ```

<strong>Exceptions:</strong>
There are exception types created for almost all the error codes above.

- MemoryAllocationException

  Derived from <code>std::bad_alloc</code>. Thrown for memory allocation errors in OpenSSL C API.

- SigningError

  Derived from <code>std::runtime_error</code>. Thrown for failures in OpenSSL APIs while signing.

- DecodeError

  Derived from <code>std::runtime_error</code>. Base class for all decoding related exceptions.

  - SignatureFormatError

    Thrown if the format of the signature is not as expected.

  - KeyNotPresentError

    Thrown if key/secret is not passed in with the decode API if the algorithm used is something other than "none".

- VerificationError

  Derived from <code>std::runtime_error</code>. Base class exception for all kinds of verification errors. Verification errors are thrown only when the verify decode parameter is set to true.

  - InvalidAlgorithmError
  - TokenExpiredError
  - InvalidIssuerError
  - InvalidAudienceError
  - InvalidSubjectError
  - InvalidIATError
  - InvalidJTIError
  - ImmatureSignatureError
  - InvalidSignatureError
  - TypeConversionError

  NOTE: See the error code section for explanation on above verification errors or checkout <code>exceptions.hpp</code> header for more details.


## Additional Header Data
Generally the header consists only of `type` and `algorithm` fields. But there could be a need to add additional header fields. For example, to provide some kind of hint about what algorithm was used to sign the JWT. Checkout JOSE header section in <a href="https://tools.ietf.org/html/rfc7515">RFC-7515</a>.

The library provides APIs to do that as well.

```cpp
#include <cassert>
#include <iostream>
#include "jwt/jwt.hpp"

int main() {
  using namespace jwt::params;

  jwt::jwt_object obj{
      headers({
        {"alg", "none"},
        {"typ", "jwt"},
        }),
      payload({
        {"iss", "arun.muralidharan"},
        {"sub", "nsfw"},
        {"x-pld", "not my ex"}
      })
  };

  bool ret = obj.header().add_header("kid", 1234567);
  assert (ret);

  ret = obj.header().add_header("crit", std::array<std::string, 1>{"exp"});
  assert (ret);

  std::error_code ec;
  auto enc_str = obj.signature();

  auto dec_obj = jwt::decode(enc_str, algorithms({"none"}), ec, verify(false));

  // Should not be a hard error in general
  assert (ec.value() == static_cast<int>(jwt::AlgorithmErrc::NoneAlgorithmUsed));
}
```


## Things for improvement
Many things!
Encoding and decoding JWT is fairly a simple task and could be done in a single source file. I have tried my best to get the APIs and design correct in how much ever time I could give for this project. Still, there are quite a few places (or all the places :( ? ) where things are not correct or may not be the best approach.

With C++, it is pretty easy to go overboard and create something very difficult or something very straightforward (not worth to be a library). My intention was to make a sane library easier for end users to use while also making the life of someone reading the source have fairly good time debugging some issue.

Things one may have questions about
- There is a string_view implementation. Why not use <code>boost::string_ref</code> ?

  Sorry, I love boost! But, do not want it to be part of dependency.
  If you use C++17 or greater `std::string_view` gets used instead and `jwt::string_view` implementation does not get included.

- You are not using the stack allocator or the shart string anywhere. Why to include it then ?

  I will be using it in few places where I am sure I need not use `std::string` especially in the signing code.

- Why the complete `nlohmann JSON` is part of your library ?

  Honestly did not know any better way. I know there are ways to use third party github repositories, but I do not know how to do that. Once I figure that out, I may move it out.

- Am I bound to use `nlohmann JSON` ? Can I use some other JSON library ?

  As of now, ys. You cannot use any other JSON library unless you change the code. I would have liked to provide some adaptors for JSON interface. Perhaps in future, if required.

- Error codes and exceptions....heh?

  Yeah, I often wonder if that was the right approach. I could have just stuck with error codes and be happy. But that was a good learning time for me.

- Where to find more about the usage ?

  Checkout the tests. It has examples for all the algorithms which are supported.

- Support for C++11 seems trivial based on the changes required. Why not support C+11 then ?

  Its 2018 now! If I ever start getting requests to have support for C++11, then I will surely consider it.

- The Metaprogramming concept checks for Sequence and Mapping looks sad.

  Yeah I know. Just hacked something very basic.


## License

MIT License

Copyright (c) 2017 Arun Muralidharan

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
