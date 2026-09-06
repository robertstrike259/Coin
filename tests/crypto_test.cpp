#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include "hash.h"
#include "ecc.h"
#include <argon2.h>
#include <cstring>

static std::string hx(const std::vector<uint8_t>& v) {
  static const char* h = "0123456789abcdef";
  std::string s;
  for (auto b : v) { s.push_back(h[b >> 4]); s.push_back(h[b & 15]); }
  return s;
}

TEST_CASE("sha256 known vectors (FIPS180)") {
  CHECK(hx(sha256_raw("")) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  CHECK(hx(sha256_raw("abc")) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  CHECK(hx(sha256_raw("The quick brown fox jumps over the lazy dog")) ==
        "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592");
  // NB: uint256::hex() displays byte-reversed (Bitcoin convention: LE internal, BE display)
  CHECK(sha256d(std::vector<uint8_t>{'a','b','c'}).hex() ==
        "58636c3ec08c12d55aedda056d602d5bcca72d8df6a69b519b72d32dc2428b4f");
}

TEST_CASE("ripemd160 known vectors") {
  CHECK(hx(ripemd160(nullptr, 0)) == "9c1185a5c5e9fc54612808977ee8f548b2258d31");
  CHECK(hx(ripemd160("abc")) == "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc");
  CHECK(hx(ripemd160("The quick brown fox jumps over the lazy dog")) ==
        "37f332f68db77bd9d7edd4969571ad671cf9dd3b");
}

TEST_CASE("argon2id official KAT (RFC 9106 / libargon2 kats)") {
  // kats/argon2id: m=32 KiB, t=3, p=4, pwd=32x01, salt=16x02, secret=8x03, ad=12x04
  std::vector<uint8_t> pwd(32, 1), salt(16, 2), sec(8, 3), ad(12, 4);
  uint8_t out[32];
  argon2_context ctx;
  memset(&ctx, 0, sizeof ctx);
  ctx.out = out; ctx.outlen = sizeof out;
  ctx.pwd = pwd.data(); ctx.pwdlen = (uint32_t)pwd.size();
  ctx.salt = salt.data(); ctx.saltlen = (uint32_t)salt.size();
  ctx.secret = sec.data(); ctx.secretlen = (uint32_t)sec.size();
  ctx.ad = ad.data(); ctx.adlen = (uint32_t)ad.size();
  ctx.t_cost = 3; ctx.m_cost = 32; ctx.lanes = 4; ctx.threads = 4;
  ctx.version = ARGON2_VERSION_13;
  CHECK(argon2id_ctx(&ctx) == ARGON2_OK);
  CHECK(hx({out, out + 32}) == "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659");
}

TEST_CASE("argon2id PoW shape: deterministic, salt/password sensitive") {
  std::vector<uint8_t> p(80, 7);
  std::vector<uint8_t> s1 = {'C','O','N','-','s','a','l','t',1};  // libargon2 needs salt >= 8 bytes
  std::vector<uint8_t> s2 = {'C','O','N','-','s','a','l','t',2};
  auto h = [&](const std::vector<uint8_t>& pw, const std::vector<uint8_t>& s) {
    uint8_t o[32];
    CHECK(argon2id_hash_raw(1, 16, 1, pw.data(), pw.size(), s.data(), s.size(), o, 32) == ARGON2_OK);
    return std::vector<uint8_t>(o, o + 32);
  };
  CHECK(h(p, s1) == h(p, s1));
  CHECK(h(p, s1) != h(p, s2));
  std::vector<uint8_t> p2 = p; p2[0] ^= 1;
  CHECK(h(p, s1) != h(p2, s1));
  uint8_t dummy[32];  // too-little-memory must report an error, not crash
  CHECK(argon2id_hash_raw(1, 7, 1, p.data(), p.size(), s1.data(), s1.size(), dummy, 32) == ARGON2_MEMORY_TOO_LITTLE);
}

TEST_CASE("secp256k1: generator point vector") {
  SecKey sk; sk.d.fill(0); sk.d[31] = 1;
  PubKey pk;
  CHECK(ecc_pubkey(sk, pk));
  CHECK(pk.d[0] == 0x02);
  CHECK(hx({pk.d.begin() + 1, pk.d.end()}) ==
        "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
}

TEST_CASE("secp256k1: sign/verify roundtrip, determinism, tamper resistance") {
  for (int i = 0; i < 4; ++i) {
    SecKey sk = ecc_generate();
    PubKey pk;
    CHECK(ecc_pubkey(sk, pk));
    bool goodPrefix = (pk.d[0] == 0x02) | (pk.d[0] == 0x03);
    CHECK(goodPrefix);
    std::vector<uint8_t> m(32);
    for (int j = 0; j < 32; ++j) m[j] = (uint8_t)(i * 61 + j * 37);
    std::array<uint8_t, 64> s1, s2;
    CHECK(ecc_sign(sk, m, s1));
    CHECK(ecc_sign(sk, m, s2));  // deterministic RFC6979
    CHECK(s1 == s2);
    CHECK(ecc_verify(pk, m, s1));
    std::vector<uint8_t> wrong = m; wrong[0] ^= 0xff;
    CHECK(!ecc_verify(pk, wrong, s1));
    auto bad = s1; bad[10] ^= 1;
    CHECK(!ecc_verify(pk, m, bad));
    SecKey other = ecc_generate();
    PubKey opk;
    CHECK(ecc_pubkey(other, opk));
    if (pk.d != opk.d) CHECK(!ecc_verify(opk, m, s1));
  }
  SecKey zero; zero.d.fill(0);
  PubKey pk;
  CHECK(!ecc_pubkey(zero, pk));  // zero key invalid
}
