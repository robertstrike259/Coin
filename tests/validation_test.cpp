#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include "validation.h"
#include "ecc.h"
#include "hash.h"
#include "pow.h"
#include <cstring>
#include <stdexcept>

// Build a funded view + valid spend, then mutate.
struct Fixture {
  SecKey sk = ecc_generate();
  PubKey pk;
  std::vector<uint8_t> pkh;
  uint256 fundTx;
  std::map<OutPoint, Coin> view;
  Fixture() {
    CHECK(ecc_pubkey(sk, pk));
    pkh = hash160_pubkey({pk.d.begin(), pk.d.end()});
    fundTx = uint256::fromHex(std::string(64, 'f'));
    view[{fundTx, 0}] = {10 * SWARF_PER_COIN, pkh, 1, false};
  }
  Transaction spend(CAmount out, CAmount fee, std::vector<uint8_t> to = {}) {
    if (to.empty()) to = pkh;
    Transaction t;
    TxIn in; in.prevTx = fundTx; in.prevOut = 0;
    t.vin = {in};
    t.vout = {{out, to}};
    CAmount change = 10 * SWARF_PER_COIN - out - fee;
    if (change > 0) t.vout.push_back({change, pkh});
    auto h = t.sighashForInput(0, pkh);
    std::vector<uint8_t> hh(h.begin(), h.end());
    std::array<uint8_t, 64> sig;
    CHECK(ecc_sign(sk, hh, sig));
    std::vector<uint8_t> ss(sig.begin(), sig.end());
    ss.insert(ss.end(), pk.d.begin(), pk.d.end());
    t.vin[0].scriptSig = ss;
    return t;
  }
  // Sign input idx of an arbitrary tx with the fixture key (for mutation tests).
  static void signAs(Transaction& t, size_t idx, const SecKey& sk, const PubKey& pk,
                     const std::vector<uint8_t>& script) {
    auto h = t.sighashForInput(idx, script);
    std::vector<uint8_t> hh(h.begin(), h.end());
    std::array<uint8_t, 64> sig;
    if (!ecc_sign(sk, hh, sig)) throw std::runtime_error("sign failed");
    std::vector<uint8_t> ss(sig.begin(), sig.end());
    ss.insert(ss.end(), pk.d.begin(), pk.d.end());
    t.vin[idx].scriptSig = ss;
  }
};

TEST_CASE("valid tx passes, fee math correct") {
  Fixture f;
  std::string why;
  auto t = f.spend(3 * SWARF_PER_COIN, 1000);
  CHECK(checkTx(t, why));
  CHECK(txFee(t, f.view) == 1000);
}

TEST_CASE("tx mutations rejected") {
  Fixture f;
  std::string why;
  auto good = f.spend(3 * SWARF_PER_COIN, 1000);
  CHECK(checkInputs(good, f.view, 1000, why)); // signed input verifies contextually
  { auto t = good; t.vin[0].scriptSig[0] ^= 1; CHECK(!checkInputs(t, f.view, 1000, why)); CHECK(why == "badsig"); }
  { auto t = good; t.vin[0].scriptSig[10] ^= 1; CHECK(checkTx(t, why)); } // structural only: sig bytes unchecked here
  { auto t = good; t.vout[0].value = 100 * SWARF_PER_COIN; CHECK(txFee(t, f.view) < 0); }
  { Transaction t; CHECK(!checkTx(t, why)); }                                     // empty
  { auto t = good; t.vout[0].pubKeyHash = {1, 2}; CHECK(!checkTx(t, why)); }      // bad pkh size
  { auto t = good; t.vin[0].scriptSig.pop_back(); CHECK(!checkTx(t, why)); }      // bad sig size
  { Transaction cb; cb.vin.resize(1); cb.vin[0].scriptSig.assign(101, 0); cb.vout = {{1, {}}}; CHECK(!checkTx(cb, why)); }  // oversized coinbase sig
}

TEST_CASE("blocks: merkle, coinbase rules, pow gate") {
  Fixture f;
  auto p = regtestParams();
  Block b;
  b.header.bits = p.genesisBits;
  Transaction cb; cb.vin.resize(1); cb.vout = {{blockReward(p, 0), std::vector<uint8_t>(20, 0)}};
  b.txs = {cb};
  b.header.merkleRoot = merkleRoot(b.txs);
  std::string why;
  // Impossibly hard bits -> PoW gate must fail deterministically
  Block hard = b; hard.header.bits = 0x01003456;
  CHECK(!checkBlock(hard, p, 0, why));
  CHECK(why == "pow");
  // Real regtest bits: mine until PoW passes, then the same block validates
  Block okb = b;
  for (uint32_t n = 0;; ++n) { okb.header.nonce = n; if (checkPow(okb.header, p)) break; }
  CHECK(checkBlock(okb, p, 0, why));  // coinbase-only block is otherwise valid
  // no coinbase
  Block b2 = b; b2.txs.clear();
  CHECK(!checkBlock(b2, p, 0, why));
  // bad merkle
  Block b3 = b; b3.header.merkleRoot = uint256();
  CHECK(!checkBlock(b3, p, 0, why));
}

TEST_CASE("checkInputs: dup inputs, missing, pkh mismatch") {
  Fixture f;
  std::string why;
  auto good = f.spend(3 * SWARF_PER_COIN, 1000);
  CHECK(checkInputs(good, f.view, 1000, why));
  { auto t = good; t.vin.push_back(t.vin[0]); // re-sign EACH input on its own digest
    Fixture::signAs(t, 0, f.sk, f.pk, f.pkh);
    Fixture::signAs(t, 1, f.sk, f.pk, f.pkh);
    CHECK(!checkInputs(t, f.view, 1000, why)); CHECK(why == "dup-input"); }
  { auto t = good; t.vin[0].prevOut = 99; CHECK(!checkInputs(t, f.view, 1000, why)); CHECK(why == "missing-input"); }
  { // wrong key signs: signature valid but pkh mismatch
    SecKey other = ecc_generate();
    PubKey opk; REQUIRE(ecc_pubkey(other, opk));
    auto t = good;
    auto h = t.sighashForInput(0, f.pkh); std::vector<uint8_t> hh(h.begin(), h.end());
    std::array<uint8_t, 64> sig; REQUIRE(ecc_sign(other, hh, sig));
    std::vector<uint8_t> ss(sig.begin(), sig.end());
    ss.insert(ss.end(), opk.d.begin(), opk.d.end());
    t.vin[0].scriptSig = ss;
    CHECK(!checkInputs(t, f.view, 1000, why)); CHECK(why == "pkh-mismatch"); }
}

TEST_CASE("signatures do not replay across inputs") {
  Fixture f;
  std::string why;
  // two inputs spending two outputs of the same key
  f.view[{f.fundTx, 1}] = {4 * SWARF_PER_COIN, f.pkh, 1, false};
  Transaction t;
  TxIn a; a.prevTx = f.fundTx; a.prevOut = 0;
  TxIn b; b.prevTx = f.fundTx; b.prevOut = 1;
  t.vin = {a, b};
  t.vout = {{13 * SWARF_PER_COIN, f.pkh}};
  Fixture::signAs(t, 0, f.sk, f.pk, f.pkh);
  Fixture::signAs(t, 1, f.sk, f.pk, f.pkh);
  CHECK(checkInputs(t, f.view, 1000, why));
  // swap the two scriptSigs: each sig is now on the wrong index -> reject
  auto evil = t;
  std::swap(evil.vin[0].scriptSig, evil.vin[1].scriptSig);
  CHECK(!checkInputs(evil, f.view, 1000, why));
  CHECK(why == "badsig");
}

TEST_CASE("coinbase maturity: 100 blocks before spend") {
  Fixture f;
  std::string why;
  // same coin, but as a coinbase mined at height 50
  std::map<OutPoint, Coin> v = f.view;
  v[{f.fundTx, 0}].coinbase = true;
  v[{f.fundTx, 0}].height = 50;
  auto good = f.spend(3 * SWARF_PER_COIN, 1000);
  CHECK(!checkInputs(good, v, 149, why)); CHECK(why == "immature");
  CHECK(!checkInputs(good, v, 99, why)); CHECK(why == "immature");
  CHECK(checkInputs(good, v, 150, why)); // 150 - 50 == maturity
  // regular (non-coinbase) coins have no maturity wait
  CHECK(checkInputs(good, f.view, 2, why));
}
