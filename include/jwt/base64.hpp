#ifndef CPP_JWT_BASE64_HPP
#define CPP_JWT_BASE64_HPP

#include <array>
#include <cassert>

namespace jwt {

/*
 * Encoding map.
 */
class EMap
{
public:
  constexpr EMap() = default;

public:
  constexpr char at(size_t pos) const noexcept
  {
    assert (pos < chars_.size());
    return chars_.at(pos);
  }

private:
  std::array<char, 64> chars_ = {
    'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
    'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z',
    '0','1','2','3','4','5','6','7','8','9',
    '+','/',
  };
};


std::string base64_encode(const char* in, size_t len)
{
  std::string result;
  result.resize(128);

  constexpr static const EMap emap{};

  int i = 0;
  int j = 0;
  for (; i < len - 2; i += 3) {
    auto& first  = in[i];
    auto& second = in[i+1];
    auto& third  = in[i+2];

    result[j++] = emap.at( (first >> 2) & 0x3F                           );
    result[j++] = emap.at(((first  & 0x03) << 4) | ((second & 0xF0) >> 4));
    result[j++] = emap.at(((second & 0x0F) << 2) | ((third  & 0xC0) >> 6));
    result[j++] = emap.at(                          (third  & 0x3F)      );
  }

  switch (len % 3) {
  case 2:
  {
    auto& first  = in[i];
    auto& second = in[i+1];

    result[j++] = emap.at( (first >> 2) & 0x3F                          );
    result[j++] = emap.at(((first & 0x03) << 4) | ((second & 0xF0) >> 4));
    result[j++] = emap.at(                         (second & 0x0F) << 2 );
    result[j++] = '=';
    break;
  }
  case 1:
  {
    auto& first = in[i];

    result[j++] = emap.at((first >> 2) & 0x3F);
    result[j++] = emap.at((first & 0x03) << 4);
    result[j++] = '=';
    result[j++] = '=';
    break;
  }
  case 0:
    break;
  };

  return result;
}



//======================= Decoder ==========================

/*
 * Decoding map.
 */
class DMap
{
public:
  constexpr DMap() = default;

public:
  constexpr char at(size_t pos) const noexcept
  {
    assert (pos < map_.size());
    return map_[pos];
  }

private:
  std::array<char, 256> map_ = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, //   0-15
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, //  16-31
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63, //  32-47
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1, //  48-63
    -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, //  64-79
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1, //  80-95
    -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, //  96-111
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1, // 112-127
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 128-143
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 144-159
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 160-175
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 176-191
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 192-207
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 208-223
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 224-239
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1  // 240-255
  };
};


std::string base64_decode(const char* in, size_t len)
{
  std::string result;
  result.resize(128);
  int i = 0;
  size_t bytes_rem = len;

  constexpr static const DMap dmap{};

  while (dmap.at(in[bytes_rem - 1]) == -1) { bytes_rem--; }

  while (bytes_rem > 4)
  {
    // Error case in input
    if (dmap.at(*in) == -1) return result;

    auto first  = dmap.at(in[0]);
    auto second = dmap.at(in[1]);
    auto third  = dmap.at(in[2]);
    auto fourth = dmap.at(in[3]);

    result[i]     = (first  << 2) | (second >> 4);
    result[i + 1] = (second << 4) | (third >> 2);
    result[i + 2] = (third  << 6) | fourth;

    bytes_rem -= 4;
    i += 3;
    in += 4;
  }

  switch(bytes_rem) {
  case 4:
  {
    auto third  = dmap.at(in[2]);
    auto fourth = dmap.at(in[3]);
    result[i + 2] = (third << 6) | fourth;
    //FALLTHROUGH
  }
  case 3:
  {
    auto second = dmap.at(in[1]);
    auto third  = dmap.at(in[2]);
    result[i + 1] = (second << 4) | (third >> 2);
    //FALLTHROUGH
  }
  case 2:
  {
    auto first  = dmap.at(in[0]);
    auto second = dmap.at(in[1]);
    result[i] = (first << 2) | (second >> 4);
  }
  };

  return result;
}

} // END namespace jwt


#endif
