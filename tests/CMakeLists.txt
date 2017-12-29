
include_directories(${OPENSSL_INCLUDE_DIR})
link_directories(${OPENSSL_LIBRARIES})

SET(CERT_ROOT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/certs")
SET(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} -DCERT_ROOT_DIR=\"\\\"${CERT_ROOT_DIR}\\\"\"")

add_executable(test_jwt_encode test_jwt_encode.cc)
target_link_libraries(test_jwt_encode ssl crypto gtest)

add_executable(test_jwt_decode test_jwt_decode.cc)
target_link_libraries(test_jwt_decode ssl crypto gtest)

add_executable(test_jwt_decode_verifiy test_jwt_decode_verifiy.cc)
target_link_libraries(test_jwt_decode_verifiy ssl crypto gtest)

add_executable(test_jwt_decode_verifiy_with_exception test_jwt_decode_verifiy_with_exception.cc)
target_link_libraries(test_jwt_decode_verifiy_with_exception ssl crypto gtest)

add_executable(test_jwt_rsa test_jwt_rsa.cc)
target_link_libraries(test_jwt_rsa ssl crypto gtest)

add_executable(test_jwt_es test_jwt_es.cc)
target_link_libraries(test_jwt_es ssl crypto gtest)
