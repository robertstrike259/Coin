#pragma once
#include "core.h"
#include "validation.h"
#include <map>
#include <set>
#include <mutex>
#include <vector>
#include <string>
// Mempool: txid -> tx, fee-ordered template. Tracks spent outpoints to stop
// double-spends across pooled transactions. Call recheck() after tip changes.
struct Mempool {
  std::mutex m; std::map<std::string,Transaction> txs; // hex txid
  std::map<OutPoint,std::string> spentBy;              // outpoint -> spending txid
  // spendHeight = height the tx would confirm at (callers pass tip height + 1).
  bool add(const Transaction& t, const std::map<OutPoint,Coin>& view, int spendHeight, std::string& why);
  std::vector<Transaction> templ() ;
  void remove(const std::vector<Transaction>& mined);
  void recheck(const std::map<OutPoint,Coin>& view, int spendHeight); // drop txs invalid under new tip
  size_t size();
};
