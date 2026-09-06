#include "pow.h"
#include <argon2.h>
#include <cstring>
// Proof of work = reference libargon2 (CC0/Apache-2.0, PHC winner):
// Argon2id(password = 80-byte header, salt = chain-domain || prevHash).
uint256 powHash(const BlockHeader& h, const ChainParams& p) {
  auto hdr = h.serialize();
  auto salt = h.powSalt(p.name);
  uint8_t out[32];
  if (argon2id_hash_raw(p.argonPasses, p.argonMemKib, 1, hdr.data(), hdr.size(), salt.data(), salt.size(), out,
                        sizeof out) != ARGON2_OK) {
    // Fail CLOSED: all-ones never meets any plausible target (pow limit << 2^256-1).
    uint256 u;
    u.d.fill(0xff);
    return u;
  }
  uint256 u;
  memcpy(u.d.data(), out, 32);
  return u;
}
#include "difficulty.h"
bool checkPow(const BlockHeader& h, const ChainParams& p) { return hashMeetsBits(powHash(h, p), h.bits); }
