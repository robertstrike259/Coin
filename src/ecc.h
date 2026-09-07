#pragma once
// ECDSA on secp256k1 via libsecp256k1 (MIT, bitcoin-core).
// Compressed pubkeys (33B), signatures 64B compact (r||s big-endian).
// Signing uses deterministic RFC6979 nonces (library default).
//
// SecKey is a hardened container, not a plain struct: bytes are cleansed
// with OPENSSL_cleanse on destroy/clear/erase, pages are mlock()ed against
// swap (best effort) and excluded from core dumps where supported, and
// moved-from objects are cleansed so no copy lingers. Signing APIs take
// const references to avoid copies. (libsecp256k1 itself may transiently
// copy the scalar on its own stack; that is outside our control.)
#include <vector>
#include <cstdint>
#include <array>
struct SecKey {
  std::array<uint8_t, 32> d;
  SecKey();
  ~SecKey();
  SecKey(const SecKey& o);
  SecKey& operator=(const SecKey& o);
  SecKey(SecKey&& o) noexcept;
  SecKey& operator=(SecKey&& o) noexcept;
  void clear(); // cleanse in place (keeps the page lock)
  void assign(const uint8_t in[32]); // cleanse old, copy new
};
struct PubKey {
  std::array<uint8_t, 33> d;
};
bool ecc_pubkey(const SecKey& sk, PubKey& pk);
bool ecc_sign(const SecKey& sk, const std::vector<uint8_t>& h32, std::array<uint8_t, 64>& sig);
bool ecc_verify(const PubKey& pk, const std::vector<uint8_t>& h32, const std::array<uint8_t, 64>& sig);
SecKey ecc_generate();
