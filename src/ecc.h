#pragma once
// ECDSA on secp256k1 via libsecp256k1 (MIT, bitcoin-core).
// Compressed pubkeys (33B), signatures 64B compact (r||s big-endian).
// Signing uses deterministic RFC6979 nonces (library default).
#include <vector>
#include <cstdint>
#include <array>
struct SecKey {
  std::array<uint8_t, 32> d;
};
struct PubKey {
  std::array<uint8_t, 33> d;
};
bool ecc_pubkey(const SecKey& sk, PubKey& pk);
bool ecc_sign(const SecKey& sk, const std::vector<uint8_t>& h32, std::array<uint8_t, 64>& sig);
bool ecc_verify(const PubKey& pk, const std::vector<uint8_t>& h32, const std::array<uint8_t, 64>& sig);
SecKey ecc_generate();
