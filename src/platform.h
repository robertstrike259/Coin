#pragma once
// Cross-platform shim (Linux / macOS / Windows): sockets, sleep, pid,
// default paths, secure RNG (OpenSSL), portable 64-bit multiply/add helpers.
// Application glue only - all crypto/math comes from OSS libs (OpenSSL,
// libsecp256k1, libargon2).
#include <cstdint>
#include <string>
#include <vector>
#include <thread>
#include <chrono>
#include <cstdlib>
#include <cerrno>
#include <csignal>
#include <openssl/rand.h>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <process.h>
#ifdef _MSC_VER
#include <intrin.h>
#endif
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#endif

namespace plt {
#ifdef _WIN32
using socket_t = SOCKET;
inline constexpr socket_t BAD_SOCKET = INVALID_SOCKET;
inline bool net_init() { WSADATA d; return WSAStartup(MAKEWORD(2, 2), &d) == 0; }
inline void net_cleanup() { WSACleanup(); }
inline void close_socket(socket_t s) { closesocket(s); }
inline int last_error() { return WSAGetLastError(); }
#else
using socket_t = int;
inline constexpr socket_t BAD_SOCKET = -1;
// Writes to a dead peer must return EPIPE, never kill the process.
inline bool net_init() {
  signal(SIGPIPE, SIG_IGN);
  return true;
}
inline void net_cleanup() {}
inline void close_socket(socket_t s) { ::close(s); }
inline int last_error() { return errno; }
#endif

inline socket_t tcp_socket() { return ::socket(AF_INET, SOCK_STREAM, 0); }

inline bool set_reuseaddr(socket_t s) {
  int one = 1;
  return ::setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char*)&one, sizeof one) == 0;
}

inline bool send_all(socket_t s, const uint8_t* d, size_t n) {
  size_t o = 0;
  while (o < n) {
#ifdef _WIN32
    int r = ::send(s, (const char*)d + o, (int)(n - o), 0);
#else
    ssize_t r = ::send(s, d + o, n - o, 0);
#endif
    if (r <= 0) return false;
    o += (size_t)r;
  }
  return true;
}

inline bool recv_all(socket_t s, uint8_t* d, size_t n) {
  size_t o = 0;
  while (o < n) {
#ifdef _WIN32
    int r = ::recv(s, (char*)d + o, (int)(n - o), 0);
#else
    ssize_t r = ::recv(s, d + o, n - o, 0);
#endif
    if (r <= 0) return false;
    o += (size_t)r;
  }
  return true;
}

// Single-shot recv used by the RPC server (request fits one segment).
inline long recv_once(socket_t s, char* buf, size_t cap) {
#ifdef _WIN32
  return (long)::recv(s, buf, (int)cap, 0);
#else
  return (long)::recv(s, buf, cap, 0);
#endif
}

inline bool bind_loopback(socket_t s, uint16_t port) {
  sockaddr_in a{};
  a.sin_family = AF_INET;
  a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  a.sin_port = htons(port);
  return ::bind(s, (sockaddr*)&a, sizeof a) == 0;
}

inline bool bind_any(socket_t s, uint16_t port) {
  sockaddr_in a{};
  a.sin_family = AF_INET;
  a.sin_addr.s_addr = htonl(INADDR_ANY);
  a.sin_port = htons(port);
  return ::bind(s, (sockaddr*)&a, sizeof a) == 0;
}

inline bool listen_on(socket_t s, int backlog = 16) { return ::listen(s, backlog) == 0; }

inline socket_t accept_one(socket_t s) { return ::accept(s, nullptr, nullptr); }

// Numeric IPv4/IPv6 literal or hostname.
inline bool connect_to(socket_t s, const std::string& host, uint16_t port) {
  sockaddr_in a{};
  a.sin_family = AF_INET;
  a.sin_port = htons(port);
#ifdef _WIN32
  if (InetPtonA(AF_INET, host.c_str(), &a.sin_addr) == 1)
    return ::connect(s, (sockaddr*)&a, sizeof a) == 0;
#else
  if (::inet_pton(AF_INET, host.c_str(), &a.sin_addr) == 1)
    return ::connect(s, (sockaddr*)&a, sizeof a) == 0;
#endif
  // Hostname fallback via getaddrinfo (portable).
  addrinfo hints{};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  addrinfo* res = nullptr;
  if (::getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0 || !res) return false;
  ((sockaddr_in*)res->ai_addr)->sin_port = htons(port);
  bool ok = ::connect(s, res->ai_addr, (int)res->ai_addrlen) == 0;
  ::freeaddrinfo(res);
  return ok;
}

inline void connect_self(uint16_t port) {  // unblock a blocking accept() on shutdown
  socket_t s = tcp_socket();
  if (s == BAD_SOCKET) return;
  sockaddr_in a{};
  a.sin_family = AF_INET;
  a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  a.sin_port = htons(port);
  ::connect(s, (sockaddr*)&a, sizeof a);
  close_socket(s);
}

inline void shutdown_socket(socket_t s) {  // unblock a thread stuck in recv()
#ifdef _WIN32
  ::shutdown(s, SD_BOTH);
#else
  ::shutdown(s, SHUT_RDWR);
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

// ~/… expansion + per-OS default datadir.
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

// Cryptographically secure RNG (OpenSSL). Never blocks on entropy.
inline bool random_bytes(uint8_t* out, size_t n) {
  return RAND_bytes(out, (int)n) == 1;
}
inline bool random_bytes(std::vector<uint8_t>& v) { return random_bytes(v.data(), v.size()); }

// Portable 64x64->128 multiply (MSVC has no __uint128_t).
// Returns low 64 bits, stores high 64 in *hi.
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
