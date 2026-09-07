#pragma once
#include "chain.h"
#include "mempool.h"
#include "platform.h"
#include <thread>
#include <atomic>
#include <functional>
#include <set>
// Minimal full P2P: TCP, magic+cmd12+len+checksum(SHA256d4), messages:
// version/verack/getheaders/headers/inv/getdata/block/tx/ping/pong.
// Headers-first IBD, block+tx relay w/ gossip, length cap (DoS shield).
struct P2P {
  Chain& chain; Mempool& pool;
  int port; std::atomic<bool> stop{false};
  std::thread srv; std::vector<std::thread> peers; std::mutex peersM;
  std::function<void(const Block&)> onBlock; // locally accepted best-tip block
  std::mutex liveM; std::set<plt::socket_t> live; // connected peer sockets
  P2P(Chain& c,Mempool& p,int port):chain(c),pool(p),port(port){}
  void start(); void halt();
  bool connectPeer(const std::string& host,int port);
  void broadcast(const std::string& cmd,const std::vector<uint8_t>& payload,plt::socket_t skip=plt::BAD_SOCKET);
  size_t peerCount() const { return npeers; }
  std::atomic<size_t> npeers{0};
};
static constexpr uint32_t P2P_MAX_MSG = 2*1024*1024 + 1024; // == MAX_BLOCK_BYTES; kept local so p2p.h needs no other deps
std::vector<uint8_t> p2pMsg(const ChainParams& p,const std::string& cmd,const std::vector<uint8_t>& payload);
