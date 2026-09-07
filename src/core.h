#pragma once
#include <vector>
#include <cstdint>
#include <string>
#include <array>
#include "amount.h"
#include "serialize.h"
#include "uint256.h"
// P2PKH-only v1: scriptPubKey = pubKeyHash(20B); scriptSig = sig(64B)||pubkey(33B).
struct TxIn { uint256 prevTx; uint32_t prevOut=0; std::vector<uint8_t> scriptSig; uint32_t seq=0xffffffff; };
struct TxOut { CAmount value=0; std::vector<uint8_t> pubKeyHash; }; // 20B
struct Transaction {
  int32_t version=1; std::vector<TxIn> vin; std::vector<TxOut> vout; uint32_t locktime=0;
  std::vector<uint8_t> serialize() const;
  static Transaction deserialize(const std::vector<uint8_t>& v);
  uint256 txid() const;
  // Per-input SIGHASH_ALL: digest commits to the whole tx with every
  // scriptSig cleared except input idx, which carries the spent output's
  // pubKeyHash (the script being satisfied). Each input signs its own digest.
  std::vector<uint8_t> sighashForInput(size_t idx, const std::vector<uint8_t>& prevPkh) const;
  bool isCoinbase() const { return vin.size()==1 && vin[0].prevTx.isZero(); }
};
struct BlockHeader {
  int32_t version=1; uint256 prevHash; uint256 merkleRoot; uint32_t time=0, bits=0, nonce=0;
  std::vector<uint8_t> serialize() const; // 80B
  static BlockHeader deserialize(SerReader& r);
  uint256 linkHash() const; // SHA256d(header) for chaining
  std::vector<uint8_t> powSalt(const char* net="main") const;
};
struct Block { BlockHeader header; std::vector<Transaction> txs;
  std::vector<uint8_t> serialize() const; static Block deserialize(const std::vector<uint8_t>& v); };
uint256 merkleRoot(const std::vector<Transaction>& txs);
// base58 + address
std::string base58Encode(const std::vector<uint8_t>& v);
std::vector<uint8_t> hash160_pubkey(const std::vector<uint8_t>& pub33);
std::string pubkeyHashToAddress(const std::vector<uint8_t>& h160, uint8_t version);
bool addressToHash(const std::string& addr, uint8_t& ver, std::vector<uint8_t>& h160);
