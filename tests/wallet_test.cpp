#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include "wallet.h"
#include "validation.h"
#include <filesystem>
#include <fstream>

TEST_CASE("wallet keys, addresses, encrypted save/load") {
  Wallet::kdfMemKib = 1024; Wallet::kdfPasses = 1; // fast KDF for tests
  Wallet w;
  std::string a1 = w.newKey(), a2 = w.newKey();
  CHECK(a1 != a2);
  CHECK(w.has(a1)); CHECK(!w.has("bogus"));
  CHECK(w.addresses().size() == 2);
  uint8_t v; std::vector<uint8_t> h;
  CHECK(addressToHash(a1, v, h));
  CHECK(h.size() == 20);
  auto path = (std::filesystem::temp_directory_path() / "coin_wtest.dat").string();
  std::filesystem::remove(path);
  w.path = path;
  CHECK(!w.save(path, "")); // empty password refused: no plaintext writes
  CHECK(w.save(path, "correct horse"));
  Wallet w2;
  CHECK(!w2.load(path, v, ""));       // password mandatory
  CHECK(!w2.load(path, v, "wrong"));  // auth tag rejects wrong password
  CHECK(w2.load(path, v, "correct horse"));
  CHECK(w2.encrypted);
  CHECK(w2.has(a1)); CHECK(w2.has(a2));
  // file must not contain plaintext keys or addresses
  { std::ifstream f(path, std::ios::binary);
    std::string raw((std::istreambuf_iterator<char>(f)), {});
    CHECK(raw.find(a1) == std::string::npos);
    CHECK(raw.rfind("CONW", 0) == 0); // magic header present
    // flip a ciphertext byte -> auth must fail
    std::string tampered = raw; tampered[40] ^= 0x01;
    { std::ofstream o(path + ".t", std::ios::binary); o.write(tampered.data(), tampered.size()); }
    Wallet w3;
    CHECK(!w3.load(path + ".t", v, "correct horse"));
    std::filesystem::remove(path + ".t"); }
  // owner-only permissions (POSIX)
#ifndef _WIN32
  { auto perms = std::filesystem::status(path).permissions();
    using P = std::filesystem::perms;
    CHECK((perms & (P::group_read | P::group_write | P::others_read | P::others_write)) == P::none); }
#endif
  std::filesystem::remove(path);
  Wallet::kdfMemKib = 65536; Wallet::kdfPasses = 3;
}

TEST_CASE("legacy plaintext wallet migrates to encrypted") {
  Wallet::kdfMemKib = 1024; Wallet::kdfPasses = 1;
  // hand-write a v1 plaintext body
  auto path = (std::filesystem::temp_directory_path() / "coin_wmig.dat").string();
  { Wallet w; std::string a = w.newKey();
    SerWriter sw; sw.varint(1); sw.str(a);
    SecKey sk = w.keys[a]; sw.bytes(sk.d.data(), 32);
    std::ofstream o(path, std::ios::binary | std::ios::trunc);
    o.write((char*)sw.v.data(), sw.v.size()); }
  Wallet m;
  CHECK(m.load(path, 0x6F)); // legacy loads without password
  CHECK(!m.encrypted);
  CHECK(m.addresses().size() == 1);
  CHECK(m.save(path, "newpass")); // migrate: overwrite encrypted
  Wallet m2;
  CHECK(m2.load(path, 0x6F, "newpass"));
  CHECK(m2.encrypted);
  CHECK(m2.addresses() == m.addresses());
  std::filesystem::remove(path);
  Wallet::kdfMemKib = 65536; Wallet::kdfPasses = 3;
}

TEST_CASE("buildSpend: exact change, insufficient, bad address") {
  Wallet w; std::string from = w.newKey(), to = w.newKey();
  PubKey pk;
  CHECK(ecc_pubkey(w.keys[from], pk));
  auto fph = hash160_pubkey({pk.d.begin(), pk.d.end()});
  uint256 ft = uint256::fromHex(std::string(64, 'e'));
  std::map<OutPoint, Coin> view;
  view[{ft, 0}] = {5 * SWARF_PER_COIN, fph, 7, false};
  std::string why;
  // spend 2 CON + 1000 swarf fee -> change 2.99999 CON
  Transaction t = buildSpend(w, view, from, to, 2 * SWARF_PER_COIN, 1000, 0x6F, why);
  REQUIRE(t.vin.size() == 1);
  REQUIRE(t.vout.size() == 2);
  CHECK(t.vout[0].value == 2 * SWARF_PER_COIN);
  CHECK(t.vout[1].value == 3 * SWARF_PER_COIN - 1000);
  CHECK(checkTx(t, why));
  CHECK(txFee(t, view) == 1000);
  // insufficient
  Transaction t2 = buildSpend(w, view, from, to, 5 * SWARF_PER_COIN, 1000, 0x6F, why);
  CHECK(t2.vin.empty()); CHECK(why == "insufficient");
  // bad destination
  Transaction t3 = buildSpend(w, view, from, "!!bad!!", 1000, 1000, 0x6F, why);
  CHECK(t3.vin.empty()); CHECK(why == "bad-to");
  // unknown sender key
  Transaction t4 = buildSpend(w, view, to + "x", to, 1000, 1000, 0x6F, why);
  CHECK(t4.vin.empty()); CHECK(why == "no-key");
}

TEST_CASE("dust change folds into fee") {
  Wallet w; std::string from = w.newKey(), to = w.newKey();
  PubKey pk; REQUIRE(ecc_pubkey(w.keys[from], pk));
  auto fph = hash160_pubkey({pk.d.begin(), pk.d.end()});
  uint256 ft = uint256::fromHex(std::string(64, 'd'));
  std::map<OutPoint, Coin> view;
  view[{ft, 0}] = {2 * SWARF_PER_COIN, fph, 7, false};
  std::string why;
  // change would be 500 < dust(1000) -> single output, fee absorbs it
  Transaction t = buildSpend(w, view, from, to, 2 * SWARF_PER_COIN - 1000 - 500, 1000, 0x6F, why);
  REQUIRE(t.vin.size() == 1);
  CHECK(t.vout.size() == 1);
  CHECK(txFee(t, view) == 1500);
}
