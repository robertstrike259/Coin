#pragma once
#include "chain.h"
#include "mempool.h"
#include <thread>
#include <atomic>
#include <functional>
#include <string>
// Minimal JSON-RPC over HTTP: getblockchaininfo, getblocktemplate, submitblock,
// sendrawtransaction, getpeerinfo, getbalance (needs address param), listunspent.
struct RpcServer {
  Chain& chain; Mempool& pool; int port; std::atomic<bool> stop{false}; std::thread th;
  std::string miningAddr;
  std::function<void(const Block&)> onBlockAccepted;      // for P2P relay
  std::function<void(const Transaction&)> onTxAccepted;   // for P2P relay
  std::function<size_t()> peerCount;                      // wired by coind
  RpcServer(Chain& c,Mempool& p,int port):chain(c),pool(p),port(port){}
  void start(); void halt();
};
std::string rpcCall(int port,const std::string& method,const std::string& paramsJson="{}");
