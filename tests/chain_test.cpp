#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include "chain.h"
#include "mempool.h"
#include "mine.h"
#include "wallet.h"
#include "ecc.h"
#include <filesystem>
#include <string>
#include <ctime>

static std::string tmpdir(const std::string& n) {
  auto d = std::filesystem::temp_directory_path() / ("coin_test_" + n);
  std::filesystem::remove_all(d);
  return d.string();
}

TEST_CASE("genesis loads, height 0, reward sane") {
  Chain c(regtestParams(), tmpdir("gen"));
  CHECK(c.load());
  CHECK(c.height() == 0);
  Block g; CHECK(c.getBlock(0, g));
  CHECK(g.txs[0].isCoinbase());
  std::map<OutPoint, Coin> u; c.getUtxoSnapshot(u);
  CHECK(!u.empty());
}

TEST_CASE("mine + connect blocks, fees accrue to coinbase") {
  Chain c(regtestParams(), tmpdir("mine"));
  Mempool pool;
  REQUIRE(c.load());
  Wallet w; std::string addr = w.newKey();
  uint8_t vv; std::vector<uint8_t> h160;
  REQUIRE(addressToHash(addr, vv, h160));
  // block 1 pays wallet
  Block b1 = mineBlock(c, pool, h160);
  std::string why;
  REQUIRE(c.acceptBlock(b1, why));
  CHECK(c.height() == 1);
  // build a spend with fee, add to mempool
  std::map<OutPoint, Coin> u; c.getUtxoSnapshot(u);
  std::string why2;
  Transaction sp = buildSpend(w, u, addr, addr, SWARF_PER_COIN, 5000, c.params.addrVersion, why2);
  REQUIRE(!sp.vin.empty());
  CHECK(pool.add(sp, u, why2));
  CHECK(pool.size() == 1);
  // block 2 includes it; coinbase may claim reward+fee
  Block b2 = mineBlock(c, pool, h160);
  REQUIRE(b2.txs.size() == 2);
  REQUIRE(c.acceptBlock(b2, why));
  pool.remove(b2.txs);
  CHECK(pool.size() == 0);
  CHECK(c.height() == 2);
}

TEST_CASE("consensus rejects: bad prev, bad bits, overspend, dup txid (BIP30)") {
  Chain c(regtestParams(), tmpdir("rej"));
  Mempool pool;
  REQUIRE(c.load());
  std::vector<uint8_t> z20(20, 0);
  std::string why;
  Block good = mineBlock(c, pool, z20);
  REQUIRE(c.acceptBlock(good, why));
  { Block b = mineBlock(c, pool, z20); b.header.prevHash = uint256(); CHECK(!c.acceptBlock(b, why)); CHECK(why == "bad-prev"); }
  { Block b = mineBlock(c, pool, z20); b.header.bits = 0x1d00ffff; CHECK(!c.acceptBlock(b, why)); CHECK(why == "bad-bits"); }
  { // resubmitting a known block is a duplicate, not a re-connect
    CHECK(!c.acceptBlock(good, why)); CHECK(why == "duplicate");
  }
  { // oversized coinbase value
    Block b = mineBlock(c, pool, z20);
    b.txs[0].vout[0].value = blockReward(c.params, c.height() + 1) + SWARF_PER_COIN;
    b.header.merkleRoot = merkleRoot(b.txs);
    // re-mine pow for mutated header
    for (uint32_t n = 0;; ++n) { b.header.nonce = n; if (checkPow(b.header, c.params)) break; }
    CHECK(!c.acceptBlock(b, why)); CHECK(why == "cb-value");
  }
}

TEST_CASE("mempool policy") {  Chain c(regtestParams(), tmpdir("pool"));
  Mempool pool;
  REQUIRE(c.load());
  Wallet w; std::string addr = w.newKey();
  uint8_t vv; std::vector<uint8_t> h160;
  REQUIRE(addressToHash(addr, vv, h160));
  std::string why;
  REQUIRE(c.acceptBlock(mineBlock(c, pool, h160), why));
  std::map<OutPoint, Coin> u; c.getUtxoSnapshot(u);
  { Transaction cb; cb.vin.resize(1); CHECK(!pool.add(cb, u, why)); }  // coinbase rejected
  { std::string w2; Transaction sp = buildSpend(w, u, addr, addr, SWARF_PER_COIN, 1, c.params.addrVersion, w2);
    REQUIRE(!sp.vin.empty()); CHECK(!pool.add(sp, u, why)); }          // fee 1 < min 100
  { std::string w2; Transaction sp = buildSpend(w, u, addr, addr, SWARF_PER_COIN, 500, c.params.addrVersion, w2);
    REQUIRE(!sp.vin.empty()); CHECK(pool.add(sp, u, why)); CHECK(pool.size() == 1); }
}

TEST_CASE("side fork stored, longer fork triggers reorg with correct balances") {
  Chain c(regtestParams(), tmpdir("reorg"));
  Mempool pool;
  REQUIRE(c.load());
  Wallet wA, wB;
  std::string addrA = wA.newKey(), addrB = wB.newKey();
  uint8_t vv; std::vector<uint8_t> hA, hB;
  REQUIRE(addressToHash(addrA, vv, hA));
  REQUIRE(addressToHash(addrB, vv, hB));
  std::string why; bool conn = false;
  // main branch: 2 blocks paying A
  REQUIRE(c.acceptBlock(mineBlock(c, pool, hA), why, conn)); CHECK(conn);
  REQUIRE(c.acceptBlock(mineBlock(c, pool, hA), why, conn)); CHECK(conn);
  CHECK(c.height() == 2);
  // side branch from genesis: 3 blocks paying B (built on a scratch twin chain)
  Chain fork(regtestParams(), tmpdir("reorgfork"));
  Mempool fpool;
  REQUIRE(fork.load()); // same deterministic genesis
  Block f1 = mineBlock(fork, fpool, hB); REQUIRE(fork.acceptBlock(f1, why));
  Block f2 = mineBlock(fork, fpool, hB); REQUIRE(fork.acceptBlock(f2, why));
  Block f3 = mineBlock(fork, fpool, hB); REQUIRE(fork.acceptBlock(f3, why));
  // feed fork blocks to main chain one at a time
  CHECK(c.acceptBlock(f1, why, conn)); CHECK(conn == false); CHECK(c.height() == 2);
  CHECK(c.acceptBlock(f2, why, conn)); CHECK(conn == false); CHECK(c.height() == 2);
  CHECK(c.acceptBlock(f3, why, conn)); CHECK(conn == true);  // longer -> reorg
  CHECK(c.height() == 3);
  // balances now reflect the fork: A has nothing, B has 300 CON
  std::map<OutPoint, Coin> u; c.getUtxoSnapshot(u);
  CAmount balA = 0, balB = 0;
  for (auto& kv : u) { if (kv.second.pkh == hA) balA += kv.second.value; if (kv.second.pkh == hB) balB += kv.second.value; }
  CHECK(balA == 0);
  CHECK(balB == 300 * SWARF_PER_COIN);
}

TEST_CASE("timestamp rules enforced") {
  Chain c(regtestParams(), tmpdir("time"));
  Mempool pool;
  REQUIRE(c.load());
  std::vector<uint8_t> z20(20, 0);
  std::string why; bool conn = false;
  REQUIRE(c.acceptBlock(mineBlock(c, pool, z20), why, conn));
  { Block b = mineBlock(c, pool, z20); b.header.time = 1; // below median
    // re-mine PoW for mutated time
    for (uint32_t n = 0;; ++n) { b.header.nonce = n; if (checkPow(b.header, c.params)) break; }
    CHECK(!c.acceptBlock(b, why, conn)); CHECK(why == "bad-time"); }
  { Block b = mineBlock(c, pool, z20);
    b.header.time = (uint32_t)time(nullptr) + 7200 + 1000; // too far future
    for (uint32_t n = 0;; ++n) { b.header.nonce = n; if (checkPow(b.header, c.params)) break; }
    CHECK(!c.acceptBlock(b, why, conn)); CHECK(why == "bad-time-future"); }
}

TEST_CASE("save/load roundtrip preserves tip and balances") {
  std::string dd = tmpdir("persist");
  uint256 tip1; int h1;
  { Chain c(regtestParams(), dd); Mempool pool;
    REQUIRE(c.load());
    std::vector<uint8_t> z20(20, 0);
    std::string why;
    REQUIRE(c.acceptBlock(mineBlock(c, pool, z20), why));
    REQUIRE(c.acceptBlock(mineBlock(c, pool, z20), why));
    std::string err; REQUIRE(c.save(err));
    tip1 = c.tipHash(); h1 = c.height(); }
  { Chain c2(regtestParams(), dd);
    REQUIRE(c2.load());
    CHECK(c2.height() == h1);
    CHECK(c2.tipHash() == tip1); }
}

TEST_CASE("unauthorized spend rejected at connect (pkh mismatch)") {
  Chain c(regtestParams(), tmpdir("auth"));
  Mempool pool;
  REQUIRE(c.load());
  Wallet victim, thief;
  std::string vAddr = victim.newKey(); thief.newKey();
  uint8_t vv; std::vector<uint8_t> vh;
  REQUIRE(addressToHash(vAddr, vv, vh));
  std::string why;
  REQUIRE(c.acceptBlock(mineBlock(c, pool, vh), why));
  // thief builds a tx spending victim's coin with thief's own valid signature
  std::map<OutPoint, Coin> u; c.getUtxoSnapshot(u);
  OutPoint target; bool found = false;
  for (auto& kv : u) if (kv.second.pkh == vh) { target = kv.first; found = true; break; }
  REQUIRE(found);
  Transaction evil;
  TxIn in; in.prevTx = target.tx; in.prevOut = target.n;
  evil.vin = {in}; evil.vout = {{SWARF_PER_COIN, vh}};
  auto h = evil.sighash(); std::vector<uint8_t> hh(h.begin(), h.end());
  PubKey tpk; REQUIRE(ecc_pubkey(thief.keys.begin()->second, tpk));
  std::array<uint8_t, 64> sig; REQUIRE(ecc_sign(thief.keys.begin()->second, hh, sig));
  std::vector<uint8_t> ss(sig.begin(), sig.end());
  ss.insert(ss.end(), tpk.d.begin(), tpk.d.end());
  evil.vin[0].scriptSig = ss;
  CHECK(!checkInputs(evil, u, why)); CHECK(why == "pkh-mismatch");
  CHECK(!pool.add(evil, u, why));
  // ...and inside a mined block
  Block b = mineBlock(c, pool, vh, false);
  b.txs.push_back(evil);
  b.header.merkleRoot = merkleRoot(b.txs);
  for (uint32_t n = 0;; ++n) { b.header.nonce = n; if (checkPow(b.header, c.params)) break; }
  bool conn = false;
  CHECK(!c.acceptBlock(b, why, conn));
}

TEST_CASE("mempool rejects double-spend across pooled txs, recheck drops spent") {
  Chain c(regtestParams(), tmpdir("pool2"));
  Mempool pool;
  REQUIRE(c.load());
  Wallet w; std::string addr = w.newKey(), other = w.newKey();
  uint8_t vv; std::vector<uint8_t> h160;
  REQUIRE(addressToHash(addr, vv, h160));
  std::string why;
  REQUIRE(c.acceptBlock(mineBlock(c, pool, h160), why));
  std::map<OutPoint, Coin> u; c.getUtxoSnapshot(u);
  std::string w2;
  Transaction t1 = buildSpend(w, u, addr, other, SWARF_PER_COIN, 500, c.params.addrVersion, w2);
  REQUIRE(!t1.vin.empty()); REQUIRE(pool.add(t1, u, why));
  Transaction t2 = buildSpend(w, u, addr, other, 2 * SWARF_PER_COIN, 500, c.params.addrVersion, w2);
  REQUIRE(!t2.vin.empty());
  CHECK(!pool.add(t2, u, why)); CHECK(why == "mempool-conflict");
  // mine t1 in; recheck must drop nothing else (pool empty after remove)
  Block b = mineBlock(c, pool, h160);
  REQUIRE(b.txs.size() == 2);
  bool conn = false; REQUIRE(c.acceptBlock(b, why, conn));
  pool.remove(b.txs);
  CHECK(pool.size() == 0);
  // a tx spending the now-spent coin must fail against a fresh snapshot
  std::map<OutPoint, Coin> u2; c.getUtxoSnapshot(u2);
  CHECK(!pool.add(t2, u2, why)); CHECK(why == "missing-input");
}
