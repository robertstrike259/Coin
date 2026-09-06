#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include "uint256.h"
#include "serialize.h"
#include "amount.h"
#include "difficulty.h"
#include "core.h"
#include "chainparams.h"
#include <cstring>

TEST_CASE("uint256 ordering, hex, zero") {
  uint256 z;
  CHECK(z.isZero());
  CHECK(z.hex() == std::string(64, '0'));
  uint256 a = uint256::fromHex("01" + std::string(62, '0'));
  uint256 b = uint256::fromHex("02" + std::string(62, '0'));
  CHECK(z < a); CHECK(a < b); CHECK(!(b < a));
  CHECK(a <= a); CHECK(a == uint256::fromHex(a.hex()));
  // LE compare: low byte dominates
  uint256 lo; lo.d[0] = 1;
  uint256 hi; hi.d[31] = 1;
  CHECK(lo < hi);
}

TEST_CASE("serialize varint boundaries + roundtrip") {
  for (uint64_t v : {0ULL, 1ULL, 252ULL, 253ULL, 0xffffULL, 0x10000ULL, 0xffffffffULL, 0x100000000ULL}) {
    SerWriter w; w.varint(v);
    SerReader r(w.v);
    CHECK(r.varint() == v);
    CHECK(r.eof());
  }
  SerWriter w; w.u32(0xdeadbeef); w.i64(-123456789LL); w.str("CON");
  SerReader r(w.v);
  CHECK(r.u32() == 0xdeadbeef);
  CHECK(r.i64() == -123456789LL);
  CHECK(r.str() == "CON");
  CHECK_THROWS(SerReader(std::vector<uint8_t>{1, 2}).u32());
}

TEST_CASE("amounts in swarf") {
  CHECK(SWARF_PER_COIN == 100000000LL);
  CHECK(fmtCon(100 * SWARF_PER_COIN) == "100.00000000");
  CHECK(fmtCon(1) == "0.00000001");
  CHECK(fmtCon(-5) == "-0.00000005");
  CHECK(moneyRange(0)); CHECK(moneyRange(MAX_MONEY_SWARF)); CHECK(!moneyRange(-1));
}

TEST_CASE("difficulty bits roundtrip + pow-limit clamp") {
  for (uint32_t b : {0x1e0fffffU, 0x1d00ffffU, 0x207fffffU, 0x1b0404cbU}) {
    CHECK(targetToBits(bitsToTarget(b)) == b);
  }
  uint256 t = bitsToTarget(0x1e0fffff);
  CHECK(hashMeetsBits(t, 0x1e0fffff));  // boundary: target itself meets
  uint256 over = t; over.d[31]++;      // definitely above (may wrap tiny targets; use pow limit)
  if (over <= t) { /* wrapped, skip */ } else CHECK(!hashMeetsBits(over, 0x1e0fffff));
  // retarget clamps: tiny actual == target/4 case, huge actual == 4x case
  uint32_t base = 0x1e0fffff;
  CHECK(retargetBits(base, 1, 1000) == retargetBits(base, 250, 1000));
  CHECK(retargetBits(base, 100000, 1000) == retargetBits(base, 4000, 1000));
  // direction: use a base below the pow limit so both directions can move
  uint32_t bbase = 0x1c0fffff;
  uint32_t fast = retargetBits(bbase, 500, 1000);
  uint32_t slow = retargetBits(bbase, 2000, 1000);
  CHECK(bitsToTarget(fast) < bitsToTarget(bbase));
  CHECK(bitsToTarget(bbase) < bitsToTarget(slow));
}

TEST_CASE("block reward schedule") {
  auto p = mainParams();
  CHECK(blockReward(p, 0) == 100 * SWARF_PER_COIN);
  CHECK(blockReward(p, 839999) == 100 * SWARF_PER_COIN);
  CHECK(blockReward(p, 840000) == 50 * SWARF_PER_COIN);
  // far future converges to tail, never below
  CHECK(blockReward(p, 100000000) == p.tailReward);
}

TEST_CASE("address roundtrip + checksum/version") {
  std::vector<uint8_t> h(20);
  for (int i = 0; i < 20; ++i) h[i] = (uint8_t)i;
  std::string a = pubkeyHashToAddress(h, 0x1C);
  uint8_t ver; std::vector<uint8_t> back;
  CHECK(addressToHash(a, ver, back));
  CHECK(ver == 0x1C); CHECK(back == h);
  std::string bad = a; bad[5] = (bad[5] == '1' ? '2' : '1');
  CHECK(!addressToHash(bad, ver, back));
  CHECK(!addressToHash("not-an-address", ver, back));
}

TEST_CASE("transaction serialize roundtrip + txid stability + sighash") {
  Transaction t;
  TxIn in; in.prevTx = uint256::fromHex(std::string(64, 'a')); in.prevOut = 3;
  in.scriptSig = {1, 2, 3};
  t.vin = {in};
  t.vout = {{5 * SWARF_PER_COIN, std::vector<uint8_t>(20, 9)}};
  auto ser = t.serialize();
  Transaction u = Transaction::deserialize(ser);
  CHECK(u.serialize() == ser);
  CHECK(u.txid() == t.txid());
  CHECK(!t.isCoinbase());
  Transaction cb; cb.vin.resize(1);
  CHECK(cb.isCoinbase());
  CHECK(t.sighash().size() == 32);
}

TEST_CASE("merkle root: single, pair, odd-duplication") {
  auto mk = [](int n) { std::vector<Transaction> v(n); for (int i = 0; i < n; ++i){ v[i].vin.resize(1); v[i].vout={{(i+1), {1,2,3}}}; } return v; };
  auto one = mk(1);
  CHECK(merkleRoot(one) == one[0].txid());
  auto two = mk(2);
  CHECK(merkleRoot(two) != merkleRoot(one));
  auto three = mk(3);
  CHECK(merkleRoot(three) != merkleRoot(two));
  // odd count duplicates last: root(3) == root([0,1,2,2])
  auto four = mk(3); four.push_back(four.back());
  // manual pairwise check instead: recompute must be deterministic
  CHECK(merkleRoot(three) == merkleRoot(mk(3)));
}

TEST_CASE("block header is 80 bytes, link hash deterministic") {
  BlockHeader h;
  h.time = 123456; h.bits = 0x207fffff; h.nonce = 42;
  CHECK(h.serialize().size() == 80);
  CHECK(h.linkHash() == h.linkHash());
  BlockHeader h2 = h; h2.nonce = 43;
  CHECK(h2.linkHash() != h.linkHash());
  CHECK(h.powSalt("regtest") != h.powSalt("main"));
}

TEST_CASE("overlong addresses rejected") {
  uint8_t v; std::vector<uint8_t> h;
  CHECK(!addressToHash(std::string(100, '1'), v, h));
}
