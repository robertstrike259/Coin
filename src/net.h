#pragma once
// Blocking TCP over standalone Asio (address-family agnostic):
// hostnames, IPv4 and IPv6 literals all go through the resolver, and
// listeners are dual-stack (IPv6 with v4-mapped fallback to IPv4).
// Threading stays std::thread; only sync socket/resolver calls are used.
#include <asio.hpp>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace net {
using tcp = asio::ip::tcp;

// Read/write exactly n bytes; false on any error (incl. orderly shutdown).
inline bool read_exact(tcp::socket& s, uint8_t* d, size_t n) {
  asio::error_code ec;
  size_t got = 0;
  while (got < n && !ec) got += asio::read(s, asio::buffer(d + got, n - got), ec);
  return !ec && got == n;
}
inline bool write_all(tcp::socket& s, const uint8_t* d, size_t n) {
  asio::error_code ec;
  size_t sent = 0;
  while (sent < n && !ec) sent += asio::write(s, asio::buffer(d + sent, n - sent), ec);
  return !ec && sent == n;
}

// Connect to a hostname or numeric IPv4/IPv6 address, trying every resolved
// endpoint in order (happy dual-stack behavior comes from resolver order).
inline bool connect(asio::io_context& io, tcp::socket& s, const std::string& host, uint16_t port) {
  asio::error_code ec;
  tcp::resolver res(io);
  auto eps = res.resolve(host, std::to_string(port), ec);
  if (ec) return false;
  asio::connect(s, eps, ec);
  return !ec;
}

// Listening acceptor on port.
// loopback=true binds 127.0.0.1 only (RPC, tests): same as the old IPv4
// behavior, never exposed externally. Dual-stack is deliberately NOT used
// here: a socket bound to ::1 specifically cannot receive IPv4-mapped
// connections, so "dual loopback" would silently drop IPv4 clients.
// loopback=false binds the dual-stack wildcard :: (accepts IPv4-mapped and
// IPv6 from anywhere), with a plain IPv4 wildcard fallback.
inline std::unique_ptr<tcp::acceptor> listen(asio::io_context& io, uint16_t port, bool loopback) {
  asio::error_code ec;
  auto acc = std::make_unique<tcp::acceptor>(io);
  if (loopback) {
    acc->open(tcp::v4(), ec);
    if (ec) return nullptr;
    acc->set_option(asio::socket_base::reuse_address(true), ec);
    acc->bind(tcp::endpoint(asio::ip::address_v4::loopback(), port), ec);
    if (ec) return nullptr;
    acc->listen(16, ec);
    if (ec) return nullptr;
    return acc;
  }
  // Attempt 1: dual-stack IPv6 wildcard. Every step is checked: in
  // particular, if v6_only(false) is refused (hardened hosts), the socket
  // would accept only IPv6 and IPv4 clients would hang forever, so fall
  // back to plain IPv4 instead.
  acc->open(tcp::v6(), ec);
  if (!ec) {
    acc->set_option(asio::socket_base::reuse_address(true), ec);
    if (!ec) acc->set_option(asio::ip::v6_only(false), ec);
    if (!ec) acc->bind(tcp::endpoint(tcp::v6(), port), ec);
    if (!ec) acc->listen(16, ec);
    if (!ec) return acc;
    acc->close(ec);
  }
  // Attempt 2: plain IPv4.
  acc->open(tcp::v4(), ec);
  if (ec) return nullptr;
  acc->set_option(asio::socket_base::reuse_address(true), ec);
  acc->bind(tcp::endpoint(tcp::v4(), port), ec);
  if (ec) return nullptr;
  acc->listen(16, ec);
  if (ec) return nullptr;
  return acc;
}
// Poke a listener to unblock a thread stuck in blocking accept().
// Closing an acceptor does NOT reliably wake a synchronous accept on all
// platforms, so halt paths connect to self first, then join.
inline void poke(uint16_t port) {
  try {
    asio::io_context io;
    tcp::socket s(io);
    connect(io, s, "127.0.0.1", port);
  } catch (...) {
  }
}
}  // namespace net
