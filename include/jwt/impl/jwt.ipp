#ifndef JWT_IPP
#define JWT_IPP

namespace jwt {

template <typename T>
std::string to_json_str(const T& obj, bool pretty)
{
  return pretty ? obj.create_json_obj().dump(2)
                : obj.create_json_obj().dump()
                ;
}


template <typename T>
std::ostream& write(std::ostream& os, const T& obj, bool pretty)
{
  pretty ? (os << std::setw(2) << obj.create_json_obj())
         : (os                 << obj.create_json_obj())
         ;

  return os;
}


template <typename T>
std::ostream& operator<< (std::ostream& os, const T& obj)
{
  os << obj.create_json_obj();
  return os;
}

} // END namespace jwt


#endif
