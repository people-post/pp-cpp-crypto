cmake_minimum_required(VERSION 3.24)
project(pp-cpp-crypto VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(PP_CRYPTO_BUILD_TESTS "Build pp-cpp-crypto unit tests" OFF)

set(PP_CRYPTO_THIRD_PARTY_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party")

# --- Vendored natives (idempotent when a parent already defined the target) ---

if(NOT TARGET sodium)
  set(SODIUM_MINIMAL OFF CACHE BOOL "" FORCE)
  add_subdirectory("${PP_CRYPTO_THIRD_PARTY_DIR}/libsodium"
                   "${CMAKE_CURRENT_BINARY_DIR}/third_party/libsodium" EXCLUDE_FROM_ALL)
endif()

if(NOT TARGET mlkem_native)
  add_subdirectory("${PP_CRYPTO_THIRD_PARTY_DIR}/mlkem-native"
                   "${CMAKE_CURRENT_BINARY_DIR}/third_party/mlkem-native" EXCLUDE_FROM_ALL)
endif()

if(NOT TARGET mldsa_native)
  add_subdirectory("${PP_CRYPTO_THIRD_PARTY_DIR}/mldsa-native"
                   "${CMAKE_CURRENT_BINARY_DIR}/third_party/mldsa-native" EXCLUDE_FROM_ALL)
endif()

# --- pp_common (Error / Roe) ---

if(NOT TARGET pp_common)
  include(FetchContent)
  set(PP_CPP_COMMON_GIT_REPOSITORY "https://github.com/people-post/pp-cpp-common.git"
    CACHE STRING "Git remote for pp-cpp-common")
  set(PP_CPP_COMMON_GIT_TAG "v0.1.0"
    CACHE STRING "Release tag on pp-cpp-common main")
  set(PP_COMMON_BUILD_TESTS OFF CACHE BOOL "Build pp-cpp-common tests" FORCE)
  FetchContent_Declare(
    pp_cpp_common
    GIT_REPOSITORY ${PP_CPP_COMMON_GIT_REPOSITORY}
    GIT_TAG ${PP_CPP_COMMON_GIT_TAG}
  )
  FetchContent_MakeAvailable(pp_cpp_common)
endif()

if(NOT TARGET pp_common)
  message(FATAL_ERROR "pp-cpp-crypto requires target pp_common")
endif()

# --- C++ wrappers ---

add_library(pp_crypto STATIC
  src/SodiumUtil.cpp
  src/MlDsa.cpp
  src/MlKem.cpp
)
add_library(pp::crypto ALIAS pp_crypto)

target_include_directories(pp_crypto PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>
)

target_link_libraries(pp_crypto PUBLIC
  pp_common
  sodium
  mldsa_native
  mlkem_native
)

if(MSVC)
  target_compile_definitions(pp_crypto PUBLIC NOMINMAX)
endif()

# FetchContent consumers link the build-tree targets. Skip install(EXPORT):
# sodium / mldsa_native / mlkem_native are EXCLUDE_FROM_ALL vendored deps.

if(PP_CRYPTO_BUILD_TESTS)
  enable_testing()
  include(FetchContent)
  set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
  FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG v1.14.0
  )
  FetchContent_MakeAvailable(googletest)

  add_executable(pp_crypto_test
    tests/ml_dsa_test.cpp
    tests/ml_kem_test.cpp
    tests/sodium_util_test.cpp)
  target_link_libraries(pp_crypto_test PRIVATE
    pp_crypto
    GTest::gtest
    GTest::gtest_main)
  include(GoogleTest)
  gtest_discover_tests(pp_crypto_test)
endif()
