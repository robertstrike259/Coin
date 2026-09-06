cmake_minimum_required(VERSION 3.24)
# doctest's old CMakeLists needs compat floor on CMake >= 4
if(CMAKE_VERSION VERSION_GREATER_EQUAL "4.0")
  set(CMAKE_POLICY_VERSION_MINIMUM 3.5 CACHE STRING "" FORCE)
endif()
project(Coin VERSION 0.1.0 LANGUAGES C CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 99)
option(WITH_QT "Build Qt GUI if Qt6 found" ON)
option(WITH_ROCKSDB "Use RocksDB if found (else embedded file DB)" ON)
option(COIN_FETCH_DEPS "Fetch OSS deps via FetchContent" ON)

if(MSVC)
  add_compile_options(/W3 /utf-8)
else()
  add_compile_options(-O2 -Wall -Wextra)
endif()

# ---- OpenSSL (hashes: SHA256/RIPEMD160, secure RNG) ----
# Linux: apt libssl-dev. macOS: brew install openssl@3 (hint below).
# Windows: vcpkg install openssl (see vcpkg.json) or -DOPENSSL_ROOT_DIR=...
if(APPLE)
  list(APPEND CMAKE_PREFIX_PATH /opt/homebrew/opt/openssl@3 /usr/local/opt/openssl@3)
endif()
find_package(OpenSSL REQUIRED)

# ---- OSS deps via FetchContent ----
include(FetchContent)
if(COIN_FETCH_DEPS)
  # libsecp256k1 (MIT, bitcoin-core) - ECDSA, replaces all hand-rolled ECC
  FetchContent_Declare(secp256k1
    GIT_REPOSITORY https://github.com/bitcoin-core/secp256k1.git
    GIT_TAG v0.5.1)
  set(SECP256K1_ENABLE_MODULE_RECOVERY OFF CACHE BOOL "" FORCE)
  set(SECP256K1_ENABLE_MODULE_EXTRAKEYS OFF CACHE BOOL "" FORCE)
  set(SECP256K1_ENABLE_MODULE_SCHNORRSIG OFF CACHE BOOL "" FORCE)
  set(SECP256K1_BUILD_TESTS OFF CACHE BOOL "" FORCE)
  set(SECP256K1_BUILD_EXHAUSTIVE_TESTS OFF CACHE BOOL "" FORCE)
  set(SECP256K1_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
  set(SECP256K1_BUILD_BENCHMARK OFF CACHE BOOL "" FORCE)
  FetchContent_MakeAvailable(secp256k1)

  # libargon2 reference (CC0/Apache-2.0, PHC winner) - Argon2id PoW.
  # Upstream has no CMake; compile its plain-C sources directly.
  FetchContent_Declare(argon2
    GIT_REPOSITORY https://github.com/P-H-C/phc-winner-argon2.git
    GIT_TAG 20190702)
  FetchContent_GetProperties(argon2)
  if(NOT argon2_POPULATED)
    FetchContent_Populate(argon2)
    add_library(argon2 STATIC
      ${argon2_SOURCE_DIR}/src/argon2.c
      ${argon2_SOURCE_DIR}/src/core.c
      ${argon2_SOURCE_DIR}/src/thread.c
      ${argon2_SOURCE_DIR}/src/encoding.c
      ${argon2_SOURCE_DIR}/src/ref.c
      ${argon2_SOURCE_DIR}/src/blake2/blake2b.c)
    target_include_directories(argon2 PUBLIC ${argon2_SOURCE_DIR}/include)
    if(NOT MSVC)
      target_compile_options(argon2 PRIVATE -O2 -pthread)
    endif()
  endif()

  # nlohmann/json (MIT) - RPC + wallet JSON
  FetchContent_Declare(json URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz)
  FetchContent_MakeAvailable(json)

  # doctest (MIT, single header) - test framework
  FetchContent_Declare(doctest
    GIT_REPOSITORY https://github.com/doctest/doctest.git
    GIT_TAG v2.4.11)
  FetchContent_MakeAvailable(doctest)
endif()

# ---- libcoin ----
file(GLOB LIBCOIN_SRC CONFIGURE_DEPENDS src/*.cpp)
add_library(coin STATIC ${LIBCOIN_SRC})
target_include_directories(coin PUBLIC src)
find_package(Threads REQUIRED)
target_link_libraries(coin PUBLIC Threads::Threads OpenSSL::Crypto secp256k1 argon2 nlohmann_json::nlohmann_json)
# Debian/Ubuntu multiarch OpenSSL headers (opensslconf.h lives in arch subdir)
foreach(_ad x86_64-linux-gnu aarch64-linux-gnu)
  if(EXISTS "${OPENSSL_INCLUDE_DIR}/${_ad}")
    target_include_directories(coin PUBLIC "${OPENSSL_INCLUDE_DIR}/${_ad}")
  endif()
endforeach()
if(WIN32)
  target_link_libraries(coin PUBLIC ws2_32)
endif()
if(WITH_ROCKSDB)
  find_library(ROCKSDB_LIB rocksdb)
  find_path(ROCKSDB_INC rocksdb/db.h)
  if(ROCKSDB_LIB AND ROCKSDB_INC)
    message(STATUS "RocksDB found, enabling")
    target_compile_definitions(coin PUBLIC COIN_WITH_ROCKSDB=1)
    target_include_directories(coin PUBLIC ${ROCKSDB_INC})
    target_link_libraries(coin PUBLIC ${ROCKSDB_LIB})
  else()
    message(STATUS "RocksDB not found, using embedded file DB")
  endif()
endif()

# ---- apps ----
foreach(app coind coin-miner coin-wallet coin-cli)
  file(GLOB S CONFIGURE_DEPENDS apps/${app}/*.cpp)
  add_executable(${app} ${S})
  target_link_libraries(${app} PRIVATE coin)
endforeach()

# ---- Qt GUI (optional, Qt is cross-platform OSS LGPL) ----
if(WITH_QT)
  find_package(Qt6 QUIET COMPONENTS Core Widgets Network)
  if(Qt6_FOUND)
    message(STATUS "Qt6 found, building coin-qt")
    set(CMAKE_AUTOMOC ON)
    file(GLOB QTSRC CONFIGURE_DEPENDS apps/coin-qt/*.cpp)
    add_executable(coin-qt ${QTSRC})
    target_link_libraries(coin-qt PRIVATE coin Qt6::Core Qt6::Widgets Qt6::Network)
  else()
    message(STATUS "Qt6 not found, skipping coin-qt (CLI wallet still builds)")
  endif()
endif()

# ---- tests (doctest) ----
enable_testing()
file(GLOB TESTSRC CONFIGURE_DEPENDS tests/*.cpp)
foreach(t ${TESTSRC})
  get_filename_component(n ${t} NAME_WE)
  add_executable(${n} ${t})
  target_link_libraries(${n} PRIVATE coin doctest::doctest)
  add_test(NAME ${n} COMMAND ${n})
endforeach()

install(TARGETS coind coin-miner coin-wallet coin-cli RUNTIME DESTINATION bin)
