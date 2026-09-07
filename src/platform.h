#pragma once
// Cross-platform shim (Linux / macOS / Windows): sleep, pid, default paths,
// secure RNG (OpenSSL), password prompt, memory locking, portable 64-bit
// multiply. Sockets live in net.h (standalone Asio). Application glue only -
// all crypto/math comes from OSS libs (OpenSSL, libsecp256k1, libargon2).
#include <cstdint>
#include <string>
#include <vector>
#include <thread>
#include <chrono>
#include <cstdlib>
#include <cerrno>
#include <csignal>
#include <climits>
#include <openssl/rand.h>

#ifdef _WIN32
#include <process.h>
#ifdef _MSC_VER
#include <intrin.h>
#endif
#else
#include <unistd.h>
#include <sys/mman.h>
#endif

#ifdef _WIN32
#include <conio.h>
#else
#include <termios.h>
#endif

namespace plt {
// Writes to a dead peer must return EPIPE, never kill the process (POSIX).
// Call once in every process that serves sockets (daemons, tests).
inline void ignore_sigpipe() {
#ifndef _WIN32
  signal(SIGPIPE, SIG_IGN);
#endif
}

inline uint64_t process_id() {
#ifdef _WIN32
  return (uint64_t)_getpid();
#else
  return (uint64_t)::getpid();
#endif
}

inline void sleep_ms(int ms) { std::this_thread::sleep_for(std::chrono::milliseconds(ms)); }
inline void sleep_sec(int s) { std::this_thread::sleep_for(std::chrono::seconds(s)); }

// ~/... expansion + per-OS default datadir.
inline std::string home_dir() {
#ifdef _WIN32
  const char* h = std::getenv("USERPROFILE");
  if (!h || !*h) h = std::getenv("HOMEDRIVE"), h = h ? h : "C:";
  return h ? h : "C:\\";
#else
  const char* h = std::getenv("HOME");
  return (h && *h) ? h : "/tmp";
#endif
}

inline std::string expand_home(const std::string& s) {
  if (!s.empty() && s[0] == '~') return home_dir() + s.substr(1);
  return s;
}

inline std::string default_datadir(const std::string& net) {
#ifdef _WIN32
  const char* app = std::getenv("APPDATA");
  std::string base = (app && *app) ? app : home_dir();
  return base + "\\Coin\\" + net;
#elif defined(__APPLE__)
  return home_dir() + "/Library/Application Support/Coin/" + net;
#else
  return home_dir() + "/.coin/" + net;
#endif
}

// Secure password prompt: no echo, empty on EOF/error. Caller cleanses after use.
inline std::string read_password(const std::string& prompt) {
  std::string out;
#ifdef _WIN32
  fputs(prompt.c_str(), stderr);
  for (;;) {
    int c = _getch();
    if (c == '\r' || c == '\n' || c == EOF) break;
    if ((c == '\b' || c == 127) && !out.empty()) {
      out.pop_back();
      continue;
    }
    if (c >= 32 && c < 127 && out.size() < 1024) out.push_back((char)c);
  }
  fputs("\n", stderr);
#else
  fputs(prompt.c_str(), stderr);
  fflush(stderr);
  termios oldT{};
  bool haveT = tcgetattr(STDIN_FILENO, &oldT) == 0;
  if (haveT) {
    termios t = oldT;
    t.c_lflag &= ~(ECHO | ECHONL);
    tcsetattr(STDIN_FILENO, TCSANOW, &t);
  }
  char buf[1024];
  if (fgets(buf, sizeof buf, stdin)) {
    out = buf;
    while (!out.empty() && (out.back() == '\n' || out.back() == '\r')) out.pop_back();
  }
  if (haveT) tcsetattr(STDIN_FILENO, TCSANOW, &oldT);
  fputs("\n", stderr);
#endif
  return out;
}
// Cryptographically secure RNG (OpenSSL). Never blocks on entropy.
// Returns false on failure: callers handling key material must retry or
// abort; callers needing only uniqueness may fall back explicitly.
inline bool random_bytes(uint8_t* out, size_t n) {
  if (n > (size_t)INT_MAX) return false;
  return RAND_bytes(out, (int)n) == 1;
}
inline bool random_bytes(std::vector<uint8_t>& v) { return random_bytes(v.data(), v.size()); }

// Lock secret pages against swap (best effort: may fail under RLIMIT_MEMLOCK
// or without privileges; cleansing remains the real guarantee either way).
// Every lock_memory must pair with exactly one unlock_memory.
inline void lock_memory(void* p, size_t n) {
  if (!p || !n) return;
#ifdef _WIN32
  VirtualLock(p, n);
#elif defined(__unix__) || defined(__APPLE__)
  mlock(p, n);
#if defined(__linux__) && defined(MADV_DONTDUMP)
  madvise(p, n, MADV_DONTDUMP); // keep secrets out of core dumps (Linux)
#endif
#endif
}
inline void unlock_memory(void* p, size_t n) {
  if (!p || !n) return;
#ifdef _WIN32
  VirtualUnlock(p, n);
#elif defined(__unix__) || defined(__APPLE__)
  munlock(p, n);
#endif
}

// Portable 64x64->128 multiply (MSVC has no __uint128_t).// Returns low 64 bits, stores high 64 in *hi.
inline uint64_t mul_u64(uint64_t a, uint64_t b, uint64_t* hi) {
#if defined(_MSC_VER) && defined(_M_X64)
  return _umul128(a, b, hi);
#elif defined(__SIZEOF_INT128__)
  __uint128_t p = (__uint128_t)a * b;
  *hi = (uint64_t)(p >> 64);
  return (uint64_t)p;
#else
  // Pure 32-bit-half schoolbook fallback (any compiler).
  uint64_t a0 = (uint32_t)a, a1 = a >> 32, b0 = (uint32_t)b, b1 = b >> 32;
  uint64_t p0 = a0 * b0, p1 = a0 * b1, p2 = a1 * b0, p3 = a1 * b1;
  uint64_t mid = p1 + p2, carry = (mid < p1) ? (uint64_t)1 << 32 : 0;
  uint64_t lo = p0 + (mid << 32);
  carry += (lo < p0);
  *hi = p3 + (mid >> 32) + carry;
  return lo;
#endif
}
}  // namespace plt
