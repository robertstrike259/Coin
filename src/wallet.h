#pragma once
#include "ecc.h"
#include "core.h"
#include "validation.h"
#include <map>
#include <string>
#include <vector>
// File wallet: N keys + addresses stored PLAINTEST in wallet.dat in v0.1
// (no encryption yet - roadmap: AES-256-GCM with scrypt KDF; do not reuse
// mainnet keys elsewhere until then).
struct Wallet {
  std::string path; uint8_t addrVersion=0x6F;
  std::map<std::string,SecKey> keys; // address -> priv
  bool load(const std::string& file,uint8_t ver); bool save(const std::string& file="") const;
  std::string newKey();
  bool has(const std::string& addr) const;
  std::vector<std::string> addresses() const;
};
Transaction buildSpend(const Wallet& w, const std::map<OutPoint,Coin>& utxo,
  const std::string& from, const std::string& to, CAmount amount, CAmount fee, uint8_t ver, std::string& why);
