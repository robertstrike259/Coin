#pragma once
#include "core.h"
#include "chainparams.h"
#include "validation.h"
#include <map>
#include <mutex>
#include <set>
#include <vector>
#include <string>
// Full-node chain state: best chain + all known side branches + undo data.
// Supports reorgs to the longest fully-valid branch, BIP30, timestamp rules.
struct BlockIndex { uint256 hash, prev; int height=0; uint32_t bits=0, time=0, nonce=0; uint256 merkle; };
struct UndoRec {
  std::vector<std::pair<OutPoint,Coin>> spent;  // inputs consumed (to restore on disconnect)
  std::vector<OutPoint> created;                // outputs created (to erase on disconnect)
};
struct Chain {
  ChainParams params; mutable std::mutex m;
  std::vector<BlockIndex> idx;                  // best-chain index (idx[h] == height h)
  std::map<std::string,int> byHash;             // best-chain hash -> height
  std::vector<Block> blocks;                    // best-chain blocks
  std::map<OutPoint,Coin> utxo;                 // best-chain UTXO set
  std::map<std::string,BlockIndex> allIndex;    // every accepted header (incl. side branches)
  std::map<std::string,Block> allBlocks;        // every accepted block body
  std::map<std::string,UndoRec> undo;           // undo for best-chain blocks
  std::set<std::string> invalid;                // branches that failed full validation
  std::string datadir;
  Chain(const ChainParams& p, std::string dd):params(p),datadir(dd){}
  bool load(std::string& err); bool save(std::string& err) const;
  bool load(){ std::string e; return load(e); }
  bool save() const { std::string e; return save(e); }
  uint256 tipHash() const; int height() const;
  uint32_t tipTime() const;
  uint32_t nextBits() const;
  Block makeGenesis();
  // Validates + connects; stores side branches; reorgs to longest valid chain.
  // why: bad-prev/dup/invalid-ancestor/bad-bits/bad-time/pow/merkle/.../reorg-failed
  // connected: true if the block is now on the best tip (false = stored side fork).
  bool acceptBlock(const Block& b, std::string& why, bool& connected);
  bool acceptBlock(const Block& b, std::string& why){ bool c=false; return acceptBlock(b,why,c); }
  bool getUtxoSnapshot(std::map<OutPoint,Coin>& o) const;
  bool getBlock(int h, Block& o) const;
  bool getBlockByHash(const uint256& h, Block& o) const;
};
