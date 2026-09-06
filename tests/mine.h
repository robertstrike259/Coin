#pragma once
// Shared test helper: build + mine regtest blocks with libargon2 PoW.
#include "chain.h"
#include "mempool.h"
#include "difficulty.h"
#include "pow.h"
#include <argon2.h>
#include <cstring>
#include <ctime>
inline Block mineBlock(Chain& chain, Mempool& pool, const std::vector<uint8_t>& payTo, bool includeMempool = true) {
  Block t;
  t.header.version = 1;
  t.header.prevHash = chain.tipHash();
  t.header.time = (uint32_t)time(nullptr);
  { Block tip; if (chain.getBlock(chain.height(), tip) && t.header.time <= tip.header.time)
      t.header.time = tip.header.time + 1; } // consensus: time must exceed median-past
  t.header.bits = chain.nextBits();
  int nh = chain.height() + 1;
  Transaction cb;
  cb.vin.resize(1);
  std::string tag = "testminer";
  for (int i = 0; i < 4; ++i) tag.push_back((nh >> (8 * i)) & 0xff);
  static uint32_t ctr = 0;
  uint32_t c = ++ctr ^ (uint32_t)time(nullptr);
  for (int i = 0; i < 4; ++i) tag.push_back((c >> (8 * i)) & 0xff);
  cb.vin[0].scriptSig = {tag.begin(), tag.end()};
  cb.vout.push_back({blockReward(chain.params, nh), payTo});
  t.txs.push_back(cb);
  if (includeMempool) for (auto& x : pool.templ()) t.txs.push_back(x);
  t.header.merkleRoot = merkleRoot(t.txs);
  for (uint32_t n = 0;; ++n) {
    t.header.nonce = n;
    if (checkPow(t.header, chain.params)) break;
    if (n > 50'000'000) throw std::runtime_error("test miner gave up");
  }
  return t;
}
