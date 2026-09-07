#include "ecc.h"
#include "platform.h"
#include <secp256k1.h>
#include <openssl/crypto.h>
#include <mutex>
#include <cstring>
SecKey::SecKey() {
  d.fill(0);
  plt::lock_memory(d.data(), d.size());
}
SecKey::~SecKey() {
  OPENSSL_cleanse(d.data(), d.size());
  plt::unlock_memory(d.data(), d.size());
}
SecKey::SecKey(const SecKey& o) : d(o.d) { plt::lock_memory(d.data(), d.size()); }
SecKey& SecKey::operator=(const SecKey& o) {
  if (this != &o) {
    OPENSSL_cleanse(d.data(), d.size());
    d = o.d;
  }
  return *this;
}
SecKey::SecKey(SecKey&& o) noexcept : d(o.d) {
  plt::lock_memory(d.data(), d.size());
  OPENSSL_cleanse(o.d.data(), o.d.size());
}
SecKey& SecKey::operator=(SecKey&& o) noexcept {
  if (this != &o) {
    OPENSSL_cleanse(d.data(), d.size());
    d = o.d;
    OPENSSL_cleanse(o.d.data(), o.d.size());
  }
  return *this;
}
void SecKey::clear() { OPENSSL_cleanse(d.data(), d.size()); d.fill(0); }
void SecKey::assign(const uint8_t in[32]) {
  OPENSSL_cleanse(d.data(), d.size());
  memcpy(d.data(), in, 32);
}
namespace {
secp256k1_context* ctx() {
  static secp256k1_context* c = nullptr;
  static std::once_flag f;
  std::call_once(f, [] { c = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY); });
  return c;
}
}  // namespace
SecKey ecc_generate() {
  SecKey k;
  do {
    if (!plt::random_bytes(k.d.data(), 32)) continue;
  } while (!secp256k1_ec_seckey_verify(ctx(), k.d.data()));
  return k;
}
bool ecc_pubkey(const SecKey& sk, PubKey& pk) {
  secp256k1_pubkey p;
  if (!secp256k1_ec_pubkey_create(ctx(), &p, sk.d.data())) return false;
  size_t n = 33;
  return secp256k1_ec_pubkey_serialize(ctx(), pk.d.data(), &n, &p, SECP256K1_EC_COMPRESSED) == 1 && n == 33;
}
bool ecc_sign(const SecKey& sk, const std::vector<uint8_t>& h32, std::array<uint8_t, 64>& sig) {
  if (h32.size() != 32) return false;
  secp256k1_ecdsa_signature s;
  if (!secp256k1_ecdsa_sign(ctx(), &s, h32.data(), sk.d.data(), nullptr, nullptr)) return false;
  secp256k1_ecdsa_signature sn;
  secp256k1_ecdsa_signature_normalize(ctx(), &sn, &s);  // low-S canonical
  return secp256k1_ecdsa_signature_serialize_compact(ctx(), sig.data(), &sn) == 1;
}
bool ecc_verify(const PubKey& pk, const std::vector<uint8_t>& h32, const std::array<uint8_t, 64>& sig) {
  if (h32.size() != 32) return false;
  if (pk.d[0] != 0x02 && pk.d[0] != 0x03) return false;
  secp256k1_pubkey p;
  if (!secp256k1_ec_pubkey_parse(ctx(), &p, pk.d.data(), 33)) return false;
  secp256k1_ecdsa_signature s;
  if (!secp256k1_ecdsa_signature_parse_compact(ctx(), &s, sig.data())) return false;
  return secp256k1_ecdsa_verify(ctx(), &s, h32.data(), &p) == 1;
}
