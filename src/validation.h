#pragma once
#include "core.h"
#include "chainparams.h"
#include <map>
#include <set>
#include <string>
// UTXO key
struct OutPoint { uint256 tx; uint32_t n=0; bool operator<(const OutPoint& o) const { return tx<o.tx || (tx==o.tx&&n<o.n); } };
struct Coin { CAmount value=0; std::vector<uint8_t> pkh; int height=0; bool coinbase=false; };
// Coinbase outputs must wait this many blocks before they can be spent
// (reorg safety). Applies on every network, like Bitcoin.
static constexpr int COINBASE_MATURITY = 100;
// Structural checks only (shapes, sizes, ranges). Signature validity needs
// the spent scripts, so it is verified in checkInputs(), not here.
bool checkTx(const Transaction& t, std::string& why);
bool checkBlock(const Block& b, const ChainParams& p, int height, std::string& why);
// Full input validation against a UTXO view: existence, no double-spend within
// the tx, coinbase maturity, pubkey authorization (pkh match), signature validity.
// spendHeight is the height of the block the tx would be included in
// (mempool callers pass tip height + 1). Fee via txFee.
bool checkInputs(const Transaction& t, const std::map<OutPoint,Coin>& view, int spendHeight, std::string& why);
CAmount txFee(const Transaction& t, const std::map<OutPoint,Coin>& view);
