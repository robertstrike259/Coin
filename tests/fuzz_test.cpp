#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include "wallet.h"
#include "core.h"
#include "serialize.h"
#include <filesystem>
#include <fstream>

// Deterministic PRNG (fixed seed): reproducible fuzz, no hangs.
struct Rng {
  uint64_t s = 0x243F6A8885A308D3ULL;
  uint64_t next() {
    s ^= s << 13; s ^= s >> 7; s ^= s << 17;
    return s;
  }
  size_t below(size_t n) { return n ? next() % n : 0; }
};

static std::vector<uint8_t> validTx() {
  Transaction t;
  TxIn in;
  in.prevTx = uint256::fromHex(std::string(64, 'a'));
  in.prevOut = 1;
  in.scriptSig = {9, 8, 7};
  t.vin = {in};
  t.vout = {{1000, std::vector<uint8_t>(20, 2)}};
  return t.serialize();
}

static std::vector<uint8_t> validWalletBody() {
  SerWriter w;
  w.varint(1);
  w.str("maddr");
  std::vector<uint8_t> k(32, 0x77);
  w.bytes(k);
  return w.v;
}

TEST_CASE("malformed wallet bodies rejected with clear outcomes") {
  Wallet::kdfMemKib = 1024; Wallet::kdfPasses = 1;
  auto path = (std::filesystem::temp_directory_path() / "coin_fuzz_w.dat").string();
  auto tryLoad = [&](const std::vector<uint8_t>& body) {
    { std::ofstream o(path, std::ios::binary | std::ios::trunc); o.write((char*)body.data(), body.size()); }
    Wallet w;
    return w.load(path, 0x6F); // legacy path, no password
  };
  { // huge key count, tiny file: must fail fast, not hang or OOM
    SerWriter w; w.varint(0xFFFFFFFFULL);
    CHECK(!tryLoad(w.v));
  }
  { // huge address length prefix
    SerWriter w; w.varint(1); w.varint(0xFFFFFFULL); w.bytes(std::vector<uint8_t>{1, 2, 3});
    CHECK(!tryLoad(w.v));
  }
  { // truncated key (31 of 32 bytes)
    SerWriter w; w.varint(1); w.str("a"); w.bytes(std::vector<uint8_t>(31, 1));
    CHECK(!tryLoad(w.v));
  }
  { // trailing garbage after valid body
    auto b = validWalletBody(); b.push_back(0xFF);
    CHECK(!tryLoad(b));
  }
  { // valid body still loads
    Wallet w;
    { std::ofstream o(path, std::ios::binary | std::ios::trunc);
      auto b = validWalletBody(); o.write((char*)b.data(), b.size()); }
    CHECK(w.load(path, 0x6F));
    CHECK(w.addresses().size() == 1);
  }
  { // empty file and garbage file
    CHECK(!tryLoad({}));
    CHECK(!tryLoad({0xFF, 0xFF, 0xFF}));
  }
  std::filesystem::remove(path);
  Wallet::kdfMemKib = 65536; Wallet::kdfPasses = 3;
}

TEST_CASE("oversize on-disk wallet refused before allocation") {
  auto path = (std::filesystem::temp_directory_path() / "coin_fuzz_big.dat").string();
  { std::ofstream o(path, std::ios::binary | std::ios::trunc); o << "x"; } // create
  std::error_code ec;
  std::filesystem::resize_file(path, MAX_WALLET_FILE + 1, ec);
  REQUIRE(!ec); // sparse: instant, no 33MB write
  Wallet w;
  CHECK(!w.load(path, 0x6F)); // file_size gate, no giant read
  std::filesystem::remove(path);
}

TEST_CASE("deterministic fuzz: tx/block/wallet parsers never crash or hang") {
  auto seed = validTx();
  Block blk;
  blk.header.bits = 0x207fffff;
  Transaction cb;
  cb.vin.resize(1);
  cb.vout = {{1, {}}};
  blk.txs = {cb};
  blk.header.merkleRoot = merkleRoot(blk.txs);
  auto bseed = blk.serialize();
  auto wseed = validWalletBody();
  auto path = (std::filesystem::temp_directory_path() / "coin_fuzz_w2.dat").string();
  Rng r;
  for (int i = 0; i < 3000; ++i) {
    int kind = r.below(3);
    // mutate: flip bytes, truncate, or inflate a length prefix
    auto mut = [&](std::vector<uint8_t> v) {
      int op = r.below(3);
      if (op == 0 && !v.empty()) v[r.below(v.size())] ^= (uint8_t)(1 + r.below(255));
      else if (op == 1 && v.size() > 1) v.resize(r.below(v.size()));
      else if (!v.empty()) v[r.below(v.size())] = (uint8_t)(0xFD + r.below(3)); // varint markers
      return v;
    };
    if (kind == 0) {
      try { Transaction::deserialize(mut(seed)); } catch (...) {}
    } else if (kind == 1) {
      try { Block::deserialize(mut(bseed)); } catch (...) {}
    } else {
      auto m = mut(wseed);
      { std::ofstream o(path, std::ios::binary | std::ios::trunc); o.write((char*)m.data(), m.size()); }
      Wallet w;
      try { w.load(path, 0x6F); } catch (...) { CHECK(false); } // load must not throw
    }
  }
  std::filesystem::remove(path);
  CHECK(true); // reaching here = no crash, no hang, no OOM
}
