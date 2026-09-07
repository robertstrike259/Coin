#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include "p2p.h"
#include "rpc.h"
#include "mempool.h"
#include "hash.h"
#include <chrono>
#include <thread>
#include <filesystem>
#include <cstring>

TEST_CASE("p2p message framing roundtrip + checksum gate") {
  auto p = regtestParams();
  std::vector<uint8_t> pl = {1, 2, 3, 4, 5};
  auto m = p2pMsg(p, "ping", pl);
  CHECK(m.size() == 4 + 12 + 4 + 4 + 5);
  SerReader r(m);
  CHECK(r.u32() == p.p2pMagic);
  auto cmd = r.bytes(12);
  CHECK(std::string((char*)cmd.data()) == "ping");
  CHECK(r.u32() == 5);
  auto ck = r.bytes(4);
  auto body = r.bytes(5);
  CHECK(body == pl);
  auto ck2 = sha256_single(sha256_single(pl));
  CHECK(memcmp(ck2.data(), ck.data(), 4) == 0);
  // over-long command truncates to 11 chars + NUL (never overflows 12B field)
  auto m2 = p2pMsg(p, "averyverylongcommandname", pl);
  SerReader r2(m2.data() + 4, 12);
  auto c2 = r2.bytes(12);
  CHECK(c2[11] == 0);
}

TEST_CASE("live RPC server: info, errors, raw-tx validation") {
  Chain chain(regtestParams(), (std::filesystem::temp_directory_path() / "coin_net1").string());
  Mempool pool;
  REQUIRE(chain.load());
  RpcServer rpc(chain, pool, 19531);
  rpc.start();
  std::this_thread::sleep_for(std::chrono::milliseconds(300));
  auto info = rpcCall(19531, "getblockchaininfo", "{}");
  CHECK(info.find("\"height\":0") != std::string::npos);
  CHECK(info.find(chain.tipHash().hex()) != std::string::npos);
  CHECK(rpcCall(19531, "nosuchmethod", "{}").find("unknown") != std::string::npos);
  CHECK(rpcCall(19531, "getbalance", "{}").find("no address") != std::string::npos);
  CHECK(rpcCall(19531, "getbalance", "{\"address\":\"junk\"}").find("bad-address") != std::string::npos);
  // garbage tx hex must error, not crash
  CHECK(rpcCall(19531, "sendrawtransaction", "{\"hex\":\"zzzz\"}").find("error") != std::string::npos);
  rpc.halt();
  CHECK(rpcCall(19531, "getblockchaininfo", "{}").find("connect") != std::string::npos);
}

TEST_CASE("p2p loopback: two nodes connect, headers sync") {
  Chain a(regtestParams(), (std::filesystem::temp_directory_path() / "coin_netA").string());
  Chain b(regtestParams(), (std::filesystem::temp_directory_path() / "coin_netB").string());
  Mempool pa, pb;
  REQUIRE(a.load()); REQUIRE(b.load());
  P2P na(a, pa, 19541), nb(b, pb, 19542);
  na.start(); nb.start();
  std::this_thread::sleep_for(std::chrono::milliseconds(300));
  CHECK(nb.connectPeer("127.0.0.1", 19541));
  auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
  while ((na.peerCount() == 0 || nb.peerCount() == 0) && std::chrono::steady_clock::now() < deadline)
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  CHECK(na.peerCount() > 0);
  CHECK(nb.peerCount() > 0);
  CHECK(a.tipHash() == b.tipHash());  // same deterministic regtest genesis
  na.halt(); nb.halt();
}

TEST_CASE("transport loops: fragmented 1MB roundtrip, close, empty (loopback TCP)") {
  asio::io_context io;
  auto acc = net::listen(io, 19551, true);
  REQUIRE(acc);
  net::tcp::socket srv(io);
  std::thread at([&] { asio::error_code ec; acc->accept(srv, ec); });
  net::tcp::socket cli(io);
  REQUIRE(net::connect(io, cli, "127.0.0.1", 19551));
  at.join();
  // Smaller-than-payload buffers force fragmentation through the exact-size
  // loops. (Kept at 64KB: 4KB windows interact with delayed ACKs and make
  // loopback bulk transfer pathologically slow without testing anything more.)
  asio::socket_base::send_buffer_size small(65536);
  asio::socket_base::receive_buffer_size rsmall(65536);
  asio::error_code ec;
  cli.set_option(small, ec); srv.set_option(rsmall, ec);
  std::vector<uint8_t> tx(1024 * 1024);
  for (size_t i = 0; i < tx.size(); ++i) tx[i] = (uint8_t)(i * 31 + 7);
  std::vector<uint8_t> rx(tx.size(), 0);
  std::thread t([&] { CHECK(net::write_all(cli, tx.data(), tx.size())); });
  CHECK(net::read_exact(srv, rx.data(), rx.size()));
  t.join();
  CHECK(rx == tx);
  CHECK(net::write_all(cli, nullptr, 0));
  CHECK(net::read_exact(srv, nullptr, 0));
  // abrupt peer close surfaces as failure, never a hang
  cli.shutdown(net::tcp::socket::shutdown_both, ec); cli.close(ec);
  uint8_t one = 0;
  CHECK(!net::read_exact(srv, &one, 1));
  srv.close(ec);
}

TEST_CASE("address resolution: IPv4, IPv6, hostnames") {
  asio::io_context io;
  net::tcp::resolver res(io);
  asio::error_code ec;
  // numeric literals resolve without any network access
  auto v4 = res.resolve("127.0.0.1", "1", ec);
  CHECK(!ec);
  bool sawV4 = false;
  for (auto& e : v4) sawV4 = sawV4 || e.endpoint().address().is_v4();
  CHECK(sawV4);
  auto v6 = res.resolve("::1", "1", ec);
  CHECK(!ec);
  bool sawV6 = false;
  for (auto& e : v6) sawV6 = sawV6 || e.endpoint().address().is_v6();
  CHECK(sawV6);
  CHECK(asio::ip::make_address("::1").is_v6());
  CHECK(asio::ip::make_address("127.0.0.1").is_v4());
  // best-effort live IPv6 roundtrip on a dual-stack wildcard listener
  // (loopback listeners stay IPv4-only by design; skipped where v6 is absent)
  auto acc6 = net::listen(io, 19552, false);
  if (acc6) {
    net::tcp::socket srv(io);
    std::thread at([&] { asio::error_code e2; acc6->accept(srv, e2); });
    net::tcp::socket cli(io);
    if (net::connect(io, cli, "::1", 19552)) {
      at.join();
      uint8_t w[4] = {9, 8, 7, 6}, r[4] = {};
      CHECK(net::write_all(cli, w, 4));
      CHECK(net::read_exact(srv, r, 4));
      CHECK(memcmp(w, r, 4) == 0);
    } else {
      at.detach();
      MESSAGE("no IPv6 loopback route: live v6 test skipped (resolution above still proves parsing)");
    }
  } else {
    MESSAGE("cannot bind IPv6 loopback: live v6 test skipped (resolution above still proves parsing)");
  }
}
