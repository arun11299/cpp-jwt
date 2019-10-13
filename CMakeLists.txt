# CMakeLists files in this project can
# refer to the root source directory of the project as ${HELLO_SOURCE_DIR} and
# to the root binary directory of the project as ${HELLO_BINARY_DIR}.

cmake_minimum_required (VERSION 3.8)
project(cpp-jwt)

#SET (CMAKE_CXX_COMPILER /usr/local/bin/g++)
# SET( CMAKE_CXX_FLAGS  "-std=c++14 -Wall -Wextra" )

add_library(${PROJECT_NAME} INTERFACE)
target_compile_options(${PROJECT_NAME} INTERFACE -Wall -Wextra)
target_compile_features(${PROJECT_NAME} INTERFACE cxx_std_14)

target_include_directories(${PROJECT_NAME} INTERFACE include)

find_package(OpenSSL REQUIRED)
target_include_directories(${PROJECT_NAME} INTERFACE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(${PROJECT_NAME} INTERFACE ${OPENSSL_LIBRARIES})

find_package(GTest REQUIRED)
target_include_directories(${PROJECT_NAME} INTERFACE ${GTEST_INCLUDE_DIRS})
target_link_libraries(${PROJECT_NAME} INTERFACE ${GTEST_LIBRARIES})


# Only if not a subproject
if(${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_CURRENT_SOURCE_DIR})
    enable_testing()

    # Recurse into the "Hello" and "Demo" subdirectories. This does not actually
    # cause another cmake executable to run. The same process will walk through
    # the project's entire directory structure.
    add_subdirectory(tests)
    add_subdirectory(examples)
endif()
