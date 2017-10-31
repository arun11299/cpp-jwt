#ifndef JWT_STRING_VIEW_IPP
#define JWT_STRING_VIEW_IPP

namespace jwt {

template <typename CharT, typename Traits>
auto basic_string_view<CharT, Traits>::find(
    const CharT* str, 
    size_type pos, 
    size_type n) const noexcept -> size_type
{
  assert (str);
  assert (n < (len_ - pos) && "Comparison size out of bounds");

  if (n == 0) {
    return pos <= len_ ? pos : npos;
  }
  if (n <= len_) {
    for (; pos <= (len_ - n); ++pos) {
      if (traits_type::eq(data_[pos], str[0]) &&
          traits_type::compare(data_ + pos + 1, str + 1, n - 1) == 0) {
        return pos;
      }
    }
  }

  return npos;
}

template <typename CharT, typename Traits>
auto basic_string_view<CharT, Traits>::rfind(
    const CharT* str,
    size_type pos,
    size_type n) const noexcept -> size_type
{
  assert (str);
  assert (pos < len_ && "Position out of bounds");

  if (n <= len_) {
    pos = std::min(len_ - n, pos);
    do {
      if (traits_type::eq(data_[pos], str[0]) &&
          traits_type::compare(data_ + pos + 1, str + 1, n - 1) == 0) {
        return pos;
      }
    } while (pos-- != 0);
  }

  return npos;
}

template <typename CharT, typename Traits>
auto basic_string_view<CharT, Traits>::find(
    const CharT ch, 
    size_type pos) const noexcept -> size_type
{
  if (pos < len_) {
    for (size_type i = pos; i < len_; ++i) {
      if (traits_type::eq(data_[i], ch)) return i;
    }
  }
  return npos;
}

template <typename CharT, typename Traits>
auto basic_string_view<CharT, Traits>::rfind(
    const CharT ch,
    size_type pos) const noexcept -> size_type
{
  if (pos < len_) {
    do {
      if (traits_type::eq(data_[pos], ch)) {
        return pos;
      }
    } while (pos-- != 0);
  }

  return npos;
}

template <typename CharT, typename Traits>
auto basic_string_view<CharT, Traits>::find_first_of(
    const CharT* str, 
    size_type pos, 
    size_type count) const noexcept -> size_type
{
  assert (str);

  for (size_type i = pos; i < len_; ++i) {
    auto p = traits_type::find(str, count, data_[i]);
    if (p) {
      return i;
    }
  }

  return npos;
}

template <typename CharT, typename Traits>
auto basic_string_view<CharT, Traits>::find_last_of(
    const CharT* str, 
    size_type pos, 
    size_type count) const noexcept -> size_type
{
  assert (str);
  assert (pos < len_ && "Position must be within the bounds of the view");
  size_type siz = len_;

  if (siz && count) {
    siz = std::min(pos, siz);

    do {
      auto p = traits_type::find(str, count, data_[siz]);
      if (p) {
        return siz;
      }
    } while (siz-- != 0);
  }

  return npos;
}

template <typename CharT, typename Traits>
auto basic_string_view<CharT, Traits>::find_first_not_of(
    const CharT* str,
    size_type pos,
    size_type n) const noexcept -> size_type
{
  assert (str);
  assert (pos < len_&& "Position must be within the bounds of the view");

  for (size_type i = pos; i < len_; ++i)
  {
    auto p = traits_type::find(str, n, data_[i]);
    if (not p) return i;
  }

  return npos;
}

template <typename CharT, typename Traits>
auto basic_string_view<CharT, Traits>::find_last_not_of(
    const CharT* str,
    size_type pos,
    size_type n) const noexcept -> size_type
{
  assert (str);
  assert (pos < len_ && "Position must be within the bounds of the view");

  do {
    for (size_type i = 0; i < n; ++i) {
      if (not traits_type::eq(data_[pos], str[i])) return pos;
    }
  } while (pos-- != 0);

  return npos;
}

template <typename CharT, typename Traits>
auto basic_string_view<CharT, Traits>::find_first_not_of(
    CharT ch,
    size_type pos) const noexcept -> size_type
{
  assert (pos < len_&& "Position must be within the bounds of the view");

  for (size_type i = pos; i < len_; ++i) {
    if (not traits_type::eq(data_[i], ch)) return i;
  }

  return npos;
}

template <typename CharT, typename Traits>
auto basic_string_view<CharT, Traits>::find_last_not_of(
    CharT ch,
    size_type pos) const noexcept -> size_type
{
  assert (pos < len_ && "Position must be within the bounds of the view");

  do {
    if (not traits_type::eq(data_[pos], ch)) return pos;
  } while (pos-- != 0);

  return npos;
}

// Comparison Operators

template <typename CharT, typename Traits>
bool operator== (basic_string_view<CharT, Traits> a,
                 basic_string_view<CharT, Traits> b) noexcept
{
  if (a.length() != b.length()) return false;
  using traits_type = typename basic_string_view<CharT, Traits>::traits_type;
  using size_type = typename basic_string_view<CharT, Traits>::size_type;

  for (size_type i = 0; i < a.length(); ++i) {
    if (not traits_type::eq(a[i], b[i])) return false;
  }

  return true;
}

template <typename CharT, typename Traits>
bool operator!= (basic_string_view<CharT, Traits> a,
                 basic_string_view<CharT, Traits> b) noexcept
{
  return not ( a == b );
}

template <typename CharT, typename Traits>
bool operator< (basic_string_view<CharT, Traits> a,
                basic_string_view<CharT, Traits> b) noexcept
{
  return a.compare(b) < 0;
}

template <typename CharT, typename Traits>
bool operator> (basic_string_view<CharT, Traits> a,
                basic_string_view<CharT, Traits> b) noexcept
{
  return a.compare(b) > 0;
}

template <typename CharT, typename Traits>
bool operator<= (basic_string_view<CharT, Traits> a,
                 basic_string_view<CharT, Traits> b) noexcept
{
  return a.compare(b) <= 0;
}

template <typename CharT, typename Traits>
bool operator>= (basic_string_view<CharT, Traits> a,
                 basic_string_view<CharT, Traits> b) noexcept
{
  return a.compare(b) >= 0;
}

template <typename CharT, typename Traits>
std::ostream& operator<< (std::ostream& os, basic_string_view<CharT, Traits> sv)
{
  os.write(sv.data(), sv.length());
  return os;
}

} // END namespace jwt

#endif
