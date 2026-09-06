#pragma once
#include "ecc.h"
#include "core.h"
#include "validation.h"
#include <map>
#include <string>
#include <vector>
// File wallet, v2 ENCRYPTED format (v1 plaintext loads for migration only,
// never written):
//
//   magic[4]="CONW" | ver u8=1 | kdf_mem_kib u32LE | kdf_passes u32LE |
//   kdf_lanes u32LE=1 | salt[16] | nonce[12] | ct_len u32LE |
//   ciphertext[ct_len] | tag[16]
//
// KDF: Argon2id(password, salt, m, t, lanes=1) -> 32-byte key (libargon2).
// AEAD: AES-256-GCM (OpenSSL EVP) with the header (magic..ct_len) as AAD,
// fresh random salt+nonce per save, all return codes checked.
// Inner plaintext = v1 body: varint n, then (address string, seckey 32B).
// Files are created 0600 and replaced atomically (tmp + rename); password
// and plaintext buffers are cleansed after use.
struct Wallet {
  std::string path; uint8_t addrVersion=0x6F;
  std::map<std::string,SecKey> keys; // address -> priv
  bool encrypted=false;              // true if loaded from / will save as v2
  // Test hook: KDF cost (production defaults are 64 MiB / 3 passes).
  static uint32_t kdfMemKib;
  static uint32_t kdfPasses;
  // Load: auto-detects v2 (needs password) vs legacy v1 plaintext (password
  // ignored, encrypted stays false). Returns false on parse/auth failure.
  bool load(const std::string& file,uint8_t ver);
  bool load(const std::string& file,uint8_t ver,const std::string& password);
  // Save: encrypted v2 only; empty password fails (no more plaintext writes).
  // No passwordless overload on purpose: every write must be encrypted.
  bool save(const std::string& file,const std::string& password) const;
  std::string newKey();
  bool has(const std::string& addr) const;
  std::vector<std::string> addresses() const;
};
// Low-level helpers (tested directly): encrypt/decrypt the v1 body.
bool walletEncryptBody(const std::vector<uint8_t>& plain, const std::string& password,
                       std::vector<uint8_t>& fileBytes);
bool walletDecryptBody(const std::vector<uint8_t>& fileBytes, const std::string& password,
                       std::vector<uint8_t>& plain, std::string& why);
Transaction buildSpend(const Wallet& w, const std::map<OutPoint,Coin>& utxo,
  const std::string& from, const std::string& to, CAmount amount, CAmount fee, uint8_t ver, std::string& why);
