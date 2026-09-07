#include "wallet.h"
#include "hash.h"
#include "platform.h"
#include <argon2.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <fstream>
#include <filesystem>
#include <cstring>

uint32_t Wallet::kdfMemKib = 65536; // 64 MiB
uint32_t Wallet::kdfPasses = 3;

namespace {
constexpr uint8_t VER = 1;
constexpr uint32_t LANES = 1;
constexpr size_t SALT_LEN = 16, NONCE_LEN = 12, TAG_LEN = 16, KEY_LEN = 32;

void put32(std::vector<uint8_t>& v, uint32_t x) {
  v.push_back(x); v.push_back(x >> 8); v.push_back(x >> 16); v.push_back(x >> 24);
}
uint32_t get32(const uint8_t* p) { return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24); }

bool deriveKey(const SecureString& password, const uint8_t* salt, uint8_t* key, uint32_t mKib, uint32_t passes) {
  if (password.empty()) return false;
  return argon2id_hash_raw(passes, mKib, LANES, password.data(), password.size(), salt, SALT_LEN, key,
                           KEY_LEN) == ARGON2_OK;
}

bool aesGcmEncrypt(const uint8_t* key, const uint8_t* nonce, const std::vector<uint8_t>& aad,
                   const std::vector<uint8_t>& plain, std::vector<uint8_t>& ct, uint8_t* tag) {
  EVP_CIPHER_CTX* c = EVP_CIPHER_CTX_new();
  if (!c) return false;
  int len = 0;
  bool ok = EVP_EncryptInit_ex(c, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
            EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, nullptr) == 1 &&
            EVP_EncryptInit_ex(c, nullptr, nullptr, key, nonce) == 1 &&
            (aad.empty() || EVP_EncryptUpdate(c, nullptr, &len, aad.data(), (int)aad.size()) == 1);
  ct.assign(plain.size(), 0);
  if (ok) {
    ok = EVP_EncryptUpdate(c, ct.data(), &len, plain.data(), (int)plain.size()) == 1 &&
         (size_t)len == plain.size();
    int flen = 0;
    ok = ok && EVP_EncryptFinal_ex(c, ct.data() + len, &flen) == 1 && flen == 0 &&
         EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag) == 1;
  }
  EVP_CIPHER_CTX_free(c);
  if (!ok) OPENSSL_cleanse(ct.data(), ct.size());
  return ok;
}

bool aesGcmDecrypt(const uint8_t* key, const uint8_t* nonce, const std::vector<uint8_t>& aad,
                   const std::vector<uint8_t>& ct, const uint8_t* tag, std::vector<uint8_t>& plain) {
  EVP_CIPHER_CTX* c = EVP_CIPHER_CTX_new();
  if (!c) return false;
  int len = 0;
  bool ok = EVP_DecryptInit_ex(c, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
            EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, nullptr) == 1 &&
            EVP_DecryptInit_ex(c, nullptr, nullptr, key, nonce) == 1 &&
            (aad.empty() || EVP_DecryptUpdate(c, nullptr, &len, aad.data(), (int)aad.size()) == 1);
  plain.assign(ct.size(), 0);
  if (ok) {
    ok = EVP_DecryptUpdate(c, plain.data(), &len, ct.data(), (int)ct.size()) == 1 &&
         (size_t)len == ct.size() &&
         EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_TAG, TAG_LEN, (void*)tag) == 1;
    int flen = 0;
    int fr = ok ? EVP_DecryptFinal_ex(c, plain.data() + len, &flen) : 0;
    ok = (fr > 0) && flen == 0;
  }
  EVP_CIPHER_CTX_free(c);
  if (!ok) {
    OPENSSL_cleanse(plain.data(), plain.size());
    plain.clear();
  }
  return ok;
}

std::vector<uint8_t> serializeBody(const std::map<std::string, SecKey>& keys) {
  SerWriter w;
  w.varint(keys.size());
  for (auto& kv : keys) {
    w.str(kv.first);
    w.bytes(kv.second.d.data(), 32);
  }
  return w.v;
}

bool parseBody(const std::vector<uint8_t>& body, std::map<std::string, SecKey>& keys, std::string& why) {
  try {
    SerReader r(body);
    auto n = (size_t)r.varintBounded(MAX_WALLET_KEYS);
    for (size_t i = 0; i < n; ++i) {
      auto a = r.strBounded(MAX_ADDR_LEN);
      auto skb = r.bytes(32); // fixed size: need() throws if truncated
      SecKey k;
      memcpy(k.d.data(), skb.data(), 32);
      keys[a] = k;
    }
    if (!r.eof()) { why = "trailing-bytes"; return false; }
    return true;
  } catch (const std::runtime_error& e) {
    why = e.what(); // "deserialize: truncated" / "oversize count" / etc.
    return false;
  } catch (...) {
    why = "parse-fail";
    return false;
  }
}
}  // namespace

bool walletEncryptBody(const std::vector<uint8_t>& plain, const SecureString& password,
                       std::vector<uint8_t>& fileBytes) {
  if (plain.size() > 16 * 1024 * 1024) return false;
  uint8_t salt[SALT_LEN], nonce[NONCE_LEN], key[KEY_LEN], tag[TAG_LEN];
  if (!plt::random_bytes(salt, sizeof salt) || !plt::random_bytes(nonce, sizeof nonce)) return false;
  if (!deriveKey(password, salt, key, Wallet::kdfMemKib, Wallet::kdfPasses)) {
    OPENSSL_cleanse(key, sizeof key);
    return false;
  }
  // Header doubles as AAD: binds version, KDF params, salt, nonce, length.
  std::vector<uint8_t> hdr = {'C', 'O', 'N', 'W', VER};
  put32(hdr, Wallet::kdfMemKib);
  put32(hdr, Wallet::kdfPasses);
  put32(hdr, LANES);
  hdr.insert(hdr.end(), salt, salt + SALT_LEN);
  hdr.insert(hdr.end(), nonce, nonce + NONCE_LEN);
  put32(hdr, (uint32_t)plain.size());
  std::vector<uint8_t> ct;
  bool ok = aesGcmEncrypt(key, nonce, hdr, plain, ct, tag);
  OPENSSL_cleanse(key, sizeof key);
  if (!ok || ct.size() != plain.size()) return false;
  fileBytes = std::move(hdr);
  fileBytes.insert(fileBytes.end(), ct.begin(), ct.end());
  fileBytes.insert(fileBytes.end(), tag, tag + TAG_LEN);
  return true;
}

bool walletDecryptBody(const std::vector<uint8_t>& fileBytes, const SecureString& password,
                       std::vector<uint8_t>& plain, std::string& why) {
  constexpr size_t HDRLEN = 4 + 1 + 4 + 4 + 4 + SALT_LEN + NONCE_LEN + 4;
  if (fileBytes.size() < HDRLEN + TAG_LEN) { why = "truncated"; return false; }
  const uint8_t* p = fileBytes.data();
  if (memcmp(p, "CONW", 4) != 0) { why = "bad-magic"; return false; }
  if (p[4] != VER) { why = "bad-version"; return false; }
  uint32_t mKib = get32(p + 5), passes = get32(p + 9), lanes = get32(p + 13);
  // Sanity bounds: refuse absurd KDF params (DoS) before allocating anything.
  if (lanes != LANES || mKib < 8 || mKib > 1024 * 1024 || passes < 1 || passes > 16) {
    why = "bad-kdf-params";
    return false;
  }
  const uint8_t* salt = p + 17;
  const uint8_t* nonce = salt + SALT_LEN;
  uint32_t ctLen = get32(nonce + NONCE_LEN);
  if (ctLen > 16 * 1024 * 1024 || HDRLEN + ctLen + TAG_LEN != fileBytes.size()) {
    why = "bad-length";
    return false;
  }
  const uint8_t* ct = nonce + NONCE_LEN + 4;
  const uint8_t* tag = ct + ctLen;
  std::vector<uint8_t> aad(p, p + HDRLEN);
  uint8_t key[KEY_LEN];
  if (!deriveKey(password, salt, key, mKib, passes)) {
    OPENSSL_cleanse(key, sizeof key);
    why = "kdf-fail";
    return false;
  }
  std::vector<uint8_t> ctV(ct, ct + ctLen);
  bool ok = aesGcmDecrypt(key, nonce, aad, ctV, tag, plain);
  OPENSSL_cleanse(key, sizeof key);
  if (!ok) {
    why = "auth-fail"; // wrong password OR tampered file: indistinguishable by design
    return false;
  }
  return true;
}

bool Wallet::load(const std::string& file, uint8_t ver) {
  SecureString empty;
  return load(file, ver, empty);
}

bool Wallet::load(const std::string& file, uint8_t ver, const SecureString& password) {
  path = file;
  addrVersion = ver;
  keys.clear();
  encrypted = false;
  std::ifstream f(file, std::ios::binary);
  if (!f.good()) return true; // no wallet yet
  try { // bound the read itself: a huge file must fail before allocation
    std::error_code ec;
    auto sz = std::filesystem::file_size(file, ec);
    if (!ec && sz > MAX_WALLET_FILE) return false;
  } catch (...) { return false; }
  std::vector<uint8_t> d((std::istreambuf_iterator<char>(f)), {});
  if (d.size() > MAX_WALLET_FILE) return false;
  if (d.size() >= 4 && memcmp(d.data(), "CONW", 4) == 0) {
    if (password.empty()) return false; // encrypted: password mandatory
    std::vector<uint8_t> body;
    std::string why;
    if (!walletDecryptBody(d, password, body, why)) return false;
    bool ok = parseBody(body, keys, why);
    OPENSSL_cleanse(body.data(), body.size());
    if (!ok) return false;
    encrypted = true;
    return true;
  }
  // Legacy v1 plaintext: load for migration; callers must re-save encrypted.
  std::string why;
  if (!parseBody(d, keys, why)) return false;
  return true;
}

bool Wallet::save(const std::string& file, const SecureString& password) const {
  std::string p = file.empty() ? path : file;
  if (p.empty() || password.empty()) return false; // never write plaintext
  std::vector<uint8_t> body = serializeBody(keys);
  std::vector<uint8_t> enc;
  bool ok = walletEncryptBody(body, password, enc);
  OPENSSL_cleanse(body.data(), body.size());
  if (!ok) return false;
  try {
    std::filesystem::path pp(p);
    if (pp.has_parent_path()) std::filesystem::create_directories(pp.parent_path());
    std::string tmp = p + ".tmp";
    { std::ofstream f(tmp, std::ios::binary | std::ios::trunc); if (!f) return false;
      f.write((char*)enc.data(), enc.size());
      f.flush();
      if (!f) return false; }
    std::error_code ec;
    std::filesystem::permissions(tmp,
        std::filesystem::perms::owner_read | std::filesystem::perms::owner_write, ec);
    std::filesystem::rename(tmp, p, ec);
    if (ec) return false;
    // Harden the final file too (rename may replace an existing looser file).
    std::filesystem::permissions(p,
        std::filesystem::perms::owner_read | std::filesystem::perms::owner_write, ec);
    return true;
  } catch (...) {
    return false;
  }
}

std::string Wallet::newKey() {
  SecKey sk = ecc_generate();
  PubKey pk;
  ecc_pubkey(sk, pk);
  auto h = hash160_pubkey({pk.d.begin(), pk.d.end()});
  auto a = pubkeyHashToAddress(h, addrVersion);
  keys[a] = sk;
  return a;
}
bool Wallet::has(const std::string& a) const { return keys.count(a); }
std::vector<std::string> Wallet::addresses() const {
  std::vector<std::string> o;
  for (auto& k : keys) o.push_back(k.first);
  return o;
}
Transaction buildSpend(const Wallet& w, const std::map<OutPoint, Coin>& utxo, const std::string& from,
                       const std::string& to, CAmount amount, CAmount fee, uint8_t ver, std::string& why) {
  static constexpr CAmount DUST = 1000;
  if (amount <= 0) { why = "bad-amount"; return {}; }
  if (fee < 0) { why = "bad-fee"; return {}; }
  uint8_t tv;
  std::vector<uint8_t> th;
  if (!addressToHash(to, tv, th)) { why = "bad-to"; return {}; }
  (void)ver;
  auto it = w.keys.find(from);
  if (it == w.keys.end()) { why = "no-key"; return {}; }
  PubKey pk;
  if (!ecc_pubkey(it->second, pk)) { why = "no-key"; return {}; }
  auto fh = hash160_pubkey({pk.d.begin(), pk.d.end()});
  Transaction t;
  CAmount in = 0;
  for (auto& kv : utxo) {
    if (kv.second.pkh == fh) {
      TxIn i;
      i.prevTx = kv.first.tx;
      i.prevOut = kv.first.n;
      t.vin.push_back(i);
      in += kv.second.value;
      if (in >= amount + fee) break;
    }
  }
  if (in < amount + fee) { why = "insufficient"; return {}; }
  TxOut o1{amount, th};
  t.vout.push_back(o1);
  CAmount change = in - amount - fee;
  if (change >= DUST) t.vout.push_back({change, fh}); // else: dust folds into fee
  auto h = t.sighash();
  std::vector<uint8_t> hh(h.begin(), h.end());
  std::array<uint8_t, 64> sig;
  if (!ecc_sign(it->second, hh, sig)) { why = "sign"; return {}; }
  std::vector<uint8_t> ss(sig.begin(), sig.end());
  ss.insert(ss.end(), pk.d.begin(), pk.d.end());
  for (auto& i : t.vin) i.scriptSig = ss;
  return t;
}
