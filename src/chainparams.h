#pragma once
#include <cstdint>
#include "amount.h"
// Chain parameters per network. All money in swarf.
struct ChainParams {
  const char* name; uint32_t p2pMagic; int defaultPort, rpcPort;
  uint32_t targetSpacing; uint32_t retargetInterval;
  uint32_t argonMemKib; uint32_t argonPasses;
  uint32_t genesisBits; int64_t genesisTime;
  CAmount genesisReward, halvingInterval, tailReward, maxBlockSize;
  uint8_t addrVersion;
};
// Chain parameters per network. All money in swarf.
// NOTE: genesis block must be findable at first load: genesisBits is easy
// (0x207fffff) on every net; difficulty retargets from there. Mainnet PoW
// memory (32 MiB, t=1) keeps CPU mining viable and verification fast;
// raise only via a planned header-version upgrade (all nodes must agree).
inline ChainParams mainParams(){ return {"main",0x434F4E44,8444,8443, 120,720, 32768,1, 0x207fffff,1767225600, 100*SWARF_PER_COIN,840000,1*SWARF_PER_COIN,2000000,0x1C}; }
inline ChainParams testParams(){ return {"testnet",0x434F4E54,18444,18443, 120,720, 16384,1, 0x207fffff,1767225600, 100*SWARF_PER_COIN,840000,1*SWARF_PER_COIN,2000000,0x6F}; }
inline ChainParams regtestParams(){ return {"regtest",0x434F4E52,19444,19443, 5,20, 1024,1, 0x207fffff,1767225600, 100*SWARF_PER_COIN,840000,1*SWARF_PER_COIN,2000000,0x6F}; }
inline CAmount blockReward(const ChainParams& p, int height){
  int halvings = height / (int)p.halvingInterval;
  CAmount r = p.genesisReward;
  for(int i=0;i<halvings;++i){ r/=2; if(r<=p.tailReward){r=p.tailReward;break;} }
  if(r < p.tailReward) r = p.tailReward;
  return r;
}
