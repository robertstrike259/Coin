#include "hash.h"
#include <openssl/evp.h>
#include <stdexcept>
#include <cstring>
namespace {
std::vector<uint8_t> evp_once(const EVP_MD* md, const uint8_t* d, size_t n) {
  EVP_MD_CTX* c = EVP_MD_CTX_new();
  if (!c) throw std::runtime_error("EVP_MD_CTX_new failed");
  std::vector<uint8_t> out(EVP_MAX_MD_SIZE);
  unsigned int olen = 0;
  bool ok = EVP_DigestInit_ex(c, md, nullptr) == 1 && EVP_DigestUpdate(c, d, n) == 1 &&
            EVP_DigestFinal_ex(c, out.data(), &olen) == 1 &&
            olen == (unsigned)EVP_MD_get_size(md) && olen <= out.size();
  EVP_MD_CTX_free(c);
  if (!ok) throw std::runtime_error("hash failed (OpenSSL provider missing algorithm?)");
  out.resize(olen);
  return out;
}
}  // namespace
std::vector<uint8_t> sha256_raw(const uint8_t* data, size_t len) { return evp_once(EVP_sha256(), data, len); }
std::vector<uint8_t> sha256_single(const std::vector<uint8_t>& v) { return sha256_raw(v.data(), v.size()); }
uint256 sha256d(const uint8_t* d, size_t n) {
  auto a = sha256_raw(d, n);
  auto b = sha256_raw(a.data(), a.size());
  uint256 u;
  memcpy(u.d.data(), b.data(), 32);
  return u;
}
uint256 sha256d(const std::vector<uint8_t>& v) { return sha256d(v.data(), v.size()); }
std::vector<uint8_t> ripemd160(const uint8_t* d, size_t n) { return evp_once(EVP_ripemd160(), d, n); }
