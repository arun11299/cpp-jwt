cmake_minimum_required(VERSION 3.5.0)
project(cpp-jwt)

option(CPP_JWT_BUILD_EXAMPLES "build examples" ON)
option(CPP_JWT_BUILD_TESTS "build tests" ON)
option(CPP_JWT_USE_VENDORED_NLOHMANN_JSON "use vendored json header" ON)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_BINARY_DIR})
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_BINARY_DIR})

# only set compiler flags if we are the main project, otherwise let the main
# project decide on the flags
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14 -Wall -Wextra")
else()

endif()

find_package(OpenSSL REQUIRED)

if(NOT CPP_JWT_USE_VENDORED_NLOHMANN_JSON)
  find_package(nlohmann_json REQUIRED)
endif()

# ##############################################################################
# LIBRARY
# ##############################################################################

add_library(${PROJECT_NAME} INTERFACE)
target_include_directories(
  ${PROJECT_NAME}
  INTERFACE $<BUILD_INTERFACE:${${PROJECT_NAME}_SOURCE_DIR}/include>
            $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
            ${OpenSSL_INCLUDE_DIR})
target_link_libraries(${PROJECT_NAME} INTERFACE ${OpenSSL_LIBRARIES})
if(NOT CPP_JWT_USE_VENDORED_NLOHMANN_JSON)
  target_link_libraries(${PROJECT_NAME} INTERFACE nlohmann_json::nlohmann_json)
  add_definitions(-DCPP_JWT_USE_VENDORED_NLOHMANN_JSON)
endif()
target_compile_features(${PROJECT_NAME} INTERFACE cxx_std_14)

# ##############################################################################
# TESTS
# ##############################################################################

if(CPP_JWT_BUILD_TESTS)
  find_package(GTest REQUIRED)
  include_directories(${GTEST_INCLUDE_DIRS})
  enable_testing()
  # Recurse into the "Hello" and "Demo" subdirectories. This does not actually
  # cause another cmake executable to run. The same process will walk through
  # the project's entire directory structure.
  add_subdirectory(tests)
endif()

# ##############################################################################
# EXAMPLES
# ##############################################################################

if(CPP_JWT_BUILD_EXAMPLES)
  add_subdirectory(examples)
endif()

# ##############################################################################
# INSTALL
# ##############################################################################

include(GNUInstallDirs)
install(
  TARGETS ${PROJECT_NAME}
  EXPORT ${PROJECT_NAME}_Targets
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/jwt/detail
        DESTINATION include/jwt)
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/jwt/impl
        DESTINATION include/jwt)
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/jwt/json
        DESTINATION include/jwt)
install(
  DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/jwt/
  DESTINATION include/jwt
  FILES_MATCHING
  PATTERN "*.hpp")
