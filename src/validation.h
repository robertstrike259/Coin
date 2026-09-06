#pragma once
#include "core.h"
#include "chainparams.h"
#include <map>
#include <set>
#include <string>
// UTXO key
struct OutPoint { uint256 tx; uint32_t n=0; bool operator<(const OutPoint& o) const { return tx<o.tx || (tx==o.tx&&n<o.n); } };
struct Coin { CAmount value=0; std::vector<uint8_t> pkh; int height=0; bool coinbase=false; };
// Structural checks only (formats, PoW-shaped sig validity). Does NOT authorize spends.
bool checkTx(const Transaction& t, std::string& why);
bool checkBlock(const Block& b, const ChainParams& p, int height, std::string& why);
// Full input validation against a UTXO view: existence, no double-spend within
// the tx, pubkey authorization (pkh match), signature validity. Fee via txFee.
bool checkInputs(const Transaction& t, const std::map<OutPoint,Coin>& view, std::string& why);
CAmount txFee(const Transaction& t, const std::map<OutPoint,Coin>& view);
