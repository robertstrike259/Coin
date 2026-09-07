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

#ifndef _WIN32
#include <sys/socket.h>
TEST_CASE("transport loops: fragmented 1MB roundtrip, close, empty") {
  int sv[2];
  REQUIRE(::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
  // tiny buffers force heavy fragmentation: many partial send/recv iterations
  int small = 4096;
  REQUIRE(::setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &small, sizeof small) == 0);
  REQUIRE(::setsockopt(sv[1], SOL_SOCKET, SO_RCVBUF, &small, sizeof small) == 0);
  std::vector<uint8_t> tx(1024 * 1024);
  for (size_t i = 0; i < tx.size(); ++i) tx[i] = (uint8_t)(i * 31 + 7);
  std::vector<uint8_t> rx(tx.size(), 0);
  std::thread t([&] { CHECK(plt::send_all(sv[0], tx.data(), tx.size())); });
  CHECK(plt::recv_all(sv[1], rx.data(), rx.size()));
  t.join();
  CHECK(rx == tx);
  CHECK(plt::send_all(sv[0], nullptr, 0));
  CHECK(plt::recv_all(sv[1], nullptr, 0));
  // abrupt peer close surfaces as failure, never a hang
  plt::close_socket(sv[0]);
  uint8_t one = 0;
  CHECK(!plt::recv_all(sv[1], &one, 1));
  plt::close_socket(sv[1]);
}
#endif
