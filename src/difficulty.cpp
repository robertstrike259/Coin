#include "difficulty.h"
#include "platform.h"
#include <cstring>
uint256 bitsToTarget(uint32_t b) {
  uint32_t exp = b >> 24, mant = b & 0xffffff;
  uint256 t;
  if (exp <= 3) {
    uint32_t v = mant >> (8 * (3 - exp));
    t.d[0] = v;
    t.d[1] = v >> 8;
    t.d[2] = v >> 16;
  } else {
    int off = exp - 3;
    for (int i = 0; i < 3; ++i) {
      if (off + i < 32) t.d[off + i] = (mant >> (8 * i)) & 0xff;
    }
  }
  return t;
}
uint32_t targetToBits(const uint256& t) {
  int sz = 32;
  while (sz > 0 && t.d[sz - 1] == 0) --sz;
  uint32_t mant = 0;
  int exp = sz;
  if (sz >= 3) {
    mant = (t.d[sz - 1] << 16) | (t.d[sz - 2] << 8) | t.d[sz - 3];
  } else if (sz == 2) {
    mant = t.d[1] << 8 | t.d[0];
    mant <<= 8;
  } else if (sz == 1) {
    mant = t.d[0];
    mant <<= 16;
  }
  if (mant & 0x800000) {
    mant >>= 8;
    exp++;
  }
  return (exp << 24) | mant;
}
bool hashMeetsBits(const uint256& h, uint32_t bits) { return h <= bitsToTarget(bits); }

namespace {
// 128-by-64 division using only 64-bit ops: q = (hi:lo)/d, r = remainder.
void div128(uint64_t hi, uint64_t lo, uint64_t d, uint64_t* q, uint64_t* r) {
  uint64_t qq = 0, rr = 0;
  for (int b = 127; b >= 0; --b) {
    uint64_t bit = (b >= 64) ? ((hi >> (b - 64)) & 1) : ((lo >> (unsigned)b) & 1);
    int ov = (rr >> 63) & 1;
    rr = (rr << 1) | bit;
    if (ov || rr >= d) {
      rr -= d;
      if (b < 64) qq |= (uint64_t)1 << b;
    }
  }
  *q = qq;
  *r = rr;
}
}  // namespace

uint32_t retargetBits(uint32_t old, int64_t actual_, int64_t target) {
  int64_t actual = actual_;
  if (actual < target / 4) actual = target / 4;
  if (actual > target * 4) actual = target * 4;
  uint256 t = bitsToTarget(old);
  // Exact integer path: t_new = t * actual / target, 256x64 multiply then divide.
  uint64_t a[4];
  for (int i = 0; i < 4; ++i) {
    a[i] = 0;
    for (int j = 0; j < 8; ++j) a[i] |= (uint64_t)t.d[i * 8 + j] << (8 * j);
  }
  uint64_t m = (uint64_t)actual;
  uint64_t nn[6] = {0, 0, 0, 0, 0, 0};
  auto add_at = [&](int j, uint64_t v) {
    while (v && j < 6) {
      uint64_t s = nn[j] + v;
      v = (s < nn[j]) ? 1 : 0;
      nn[j] = s;
      ++j;
    }
  };
  for (int i = 0; i < 4; ++i) {
    uint64_t hi = 0;
    uint64_t lo = plt::mul_u64(a[i], m, &hi);  // portable (MSVC-safe, pure fallback)
    add_at(i, lo);
    add_at(i + 1, hi);
  }
  uint64_t q[6] = {0};
  uint64_t rem = 0;
  for (int i = 5; i >= 0; --i) {
    uint64_t qi, ri;
    div128(rem, nn[i], (uint64_t)target, &qi, &ri);
    q[i] = qi;
    rem = ri;
  }
  uint256 nt;
  for (int i = 0; i < 4; ++i) {
    uint64_t v = q[i];
    for (int j = 0; j < 8; ++j) nt.d[i * 8 + j] = (v >> (8 * j)) & 0xff;
  }
  uint256 lim = bitsToTarget(0x1e0fffff);
  if (lim < nt) nt = lim;
  return targetToBits(nt);
}
