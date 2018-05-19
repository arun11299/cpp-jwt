# CMakeLists files in this project can
# refer to the root source directory of the project as ${HELLO_SOURCE_DIR} and
# to the root binary directory of the project as ${HELLO_BINARY_DIR}.

cmake_minimum_required (VERSION 2.8.11)
project (cpp-jwt)

#SET (CMAKE_CXX_COMPILER /usr/local/bin/g++)
SET( CMAKE_CXX_FLAGS  "-std=c++14 -Wall" )

include_directories (include)

#find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})
link_directories(${OPENSSL_LIBRARIES})

# Recurse into the "Hello" and "Demo" subdirectories. This does not actually
# cause another cmake executable to run. The same process will walk through
# the project's entire directory structure.
add_subdirectory (tests)

add_subdirectory (examples)
