#pragma once
#include "chain.h"
#include "mempool.h"
#include "platform.h"
#include "net.h"
#include <thread>
#include <atomic>
#include <functional>
#include <memory>
#include <set>
// Minimal full P2P over Asio TCP (dual-stack IPv4/IPv6):
// magic+cmd12+len+checksum(SHA256d4), messages:
// version/verack/getheaders/headers/inv/getdata/block/tx/ping/pong.
// Headers-first IBD, block+tx relay w/ gossip, length cap (DoS shield).
struct P2P {
  Chain& chain; Mempool& pool;
  int port; std::atomic<bool> stop{false};
  asio::io_context io;
  std::shared_ptr<net::tcp::acceptor> acceptor; // set by start(), closed by halt()
  std::thread srv; std::vector<std::thread> peers; std::mutex peersM;
  std::function<void(const Block&)> onBlock; // locally accepted best-tip block
  std::mutex liveM; std::set<std::shared_ptr<net::tcp::socket>> live;
  P2P(Chain& c,Mempool& p,int port):chain(c),pool(p),port(port){}
  void start(); void halt();
  bool connectPeer(const std::string& host,int port);
  void broadcast(const std::string& cmd,const std::vector<uint8_t>& payload,
                 net::tcp::socket* skip=nullptr);
  size_t peerCount() const { return npeers; }
  std::atomic<size_t> npeers{0};
};
static constexpr uint32_t P2P_MAX_MSG = 2*1024*1024 + 1024; // == MAX_BLOCK_BYTES
std::vector<uint8_t> p2pMsg(const ChainParams& p,const std::string& cmd,const std::vector<uint8_t>& payload);
