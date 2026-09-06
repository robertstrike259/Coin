#pragma once
// Hash primitives via OpenSSL (OSS, BSD-style license):
// SHA256 / SHA256d for txids, merkle, checksums; RIPEMD160 for hash160.
#include <cstdint>
#include <vector>
#include <string>
#include "uint256.h"
std::vector<uint8_t> sha256_raw(const uint8_t* data, size_t len);
inline std::vector<uint8_t> sha256_raw(const std::vector<uint8_t>& v) { return sha256_raw(v.data(), v.size()); }
inline std::vector<uint8_t> sha256_raw(const std::string& s) { return sha256_raw((const uint8_t*)s.data(), s.size()); }
std::vector<uint8_t> sha256_single(const std::vector<uint8_t>& v);
uint256 sha256d(const std::vector<uint8_t>& v);
uint256 sha256d(const uint8_t* d, size_t n);
std::vector<uint8_t> ripemd160(const uint8_t* d, size_t n);
inline std::vector<uint8_t> ripemd160(const std::vector<uint8_t>& v) { return ripemd160(v.data(), v.size()); }
inline std::vector<uint8_t> ripemd160(const std::string& s) { return ripemd160((const uint8_t*)s.data(), s.size()); }
