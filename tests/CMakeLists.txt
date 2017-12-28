
add_library(libgtest IMPORTED STATIC GLOBAL)
add_executable (test_jwt_encode test_jwt_encode.cc)
target_link_libraries(test_jwt_encode ssl crypto gtest)
