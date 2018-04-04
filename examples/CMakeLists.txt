
include_directories(${OPENSSL_INCLUDE_DIR})
link_directories(${OPENSSL_LIBRARIES})

SET(CERT_ROOT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/rsa_256")
SET(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} -DCERT_ROOT_DIR=\"\\\"${CERT_ROOT_DIR}\\\"\"")

add_executable(simple_ex1 simple_ex1.cc)
target_link_libraries(simple_ex1 ssl crypto gtest)

add_executable(simple_ex2 simple_ex2.cc)
target_link_libraries(simple_ex2 ssl crypto gtest)

add_executable(simple_ex3_rsa simple_ex3_rsa.cc)
target_link_libraries(simple_ex3_rsa ssl crypto gtest)
