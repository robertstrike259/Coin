#include "validation.h"
#include "ecc.h"
bool checkTx(const Transaction& t,std::string& why){
  if(t.vin.empty()||t.vout.empty()){why="empty";return false;}
  CAmount o=0; for(auto&x:t.vout){ if(!moneyRange(x.value)){why="value";return false;} o+=x.value; if(!moneyRange(o)){why="overflow";return false;} if(!t.isCoinbase()&&x.pubKeyHash.size()!=20){why="pkh";return false;} }
  if(t.isCoinbase()){ if(t.vin[0].scriptSig.size()>100){why="cb-size";return false;} return true; }
  // Structural only: 64B sig + 33B compressed pubkey per input. Signature
  // VALIDITY needs the spent scripts, so it is checked in checkInputs().
  for(auto&i:t.vin){ if(i.scriptSig.size()!=97){why="sigsize";return false;}
    uint8_t prefix=i.scriptSig[64];
    if(prefix!=0x02&&prefix!=0x03){why="badpubkey";return false;} }
  return true;
}
bool checkInputs(const Transaction& t,const std::map<OutPoint,Coin>& view,int spendHeight,std::string& why){
  if(t.isCoinbase()){why="coinbase";return false;}
  std::set<std::pair<std::string,uint32_t>> seen;
  for(size_t k=0;k<t.vin.size();++k){
    auto& i=t.vin[k];
    OutPoint o{i.prevTx,i.prevOut};
    auto key=std::make_pair(i.prevTx.hex(),i.prevOut);
    if(!seen.insert(key).second){why="dup-input";return false;}
    auto it=view.find(o); if(it==view.end()){why="missing-input";return false;}
    if(it->second.coinbase && spendHeight-it->second.height<COINBASE_MATURITY){why="immature";return false;}
    if(i.scriptSig.size()!=97){why="sigsize";return false;}
    std::array<uint8_t,64> sig; memcpy(sig.data(),i.scriptSig.data(),64);
    PubKey pk; memcpy(pk.d.data(),i.scriptSig.data()+64,33);
    if(pk.d[0]!=0x02&&pk.d[0]!=0x03){why="badpubkey";return false;}
    // AUTHORIZATION: signer must own the output being spent
    if(hash160_pubkey({pk.d.begin(),pk.d.end()})!=it->second.pkh){why="pkh-mismatch";return false;}
    // Each input is verified against its OWN sighash (bound to its index
    // and script), so signatures are not replayable across inputs.
    auto h=t.sighashForInput(k,it->second.pkh); std::vector<uint8_t> hh(h.begin(),h.end());
    if(!ecc_verify(pk,hh,sig)){why="badsig";return false;}
  }
  return true;
}
#include "difficulty.h"
#include "pow.h"
#include "merkle.h"
bool checkBlock(const Block& b,const ChainParams& p,int height,std::string& why){
  if(b.txs.empty()||b.txs.size()>10000){why="txcount";return false;}
  if(!b.txs[0].isCoinbase()){why="nocoinbase";return false;}
  for(size_t i=1;i<b.txs.size();++i) if(b.txs[i].isCoinbase()){why="multicb";return false;}
  if(merkleRoot(b.txs)!=b.header.merkleRoot){why="merkle";return false;}
  if(!checkPow(b.header,p)){why="pow";return false;}
  size_t sz=b.serialize().size(); if(sz>(size_t)p.maxBlockSize){why="size";return false;}
  for(auto&t:b.txs) if(!checkTx(t,why)) return false;
  (void)height; return true;
}
CAmount txFee(const Transaction& t,const std::map<OutPoint,Coin>& v){
  if(t.isCoinbase()) return 0; CAmount in=0; for(auto&i:t.vin){ auto it=v.find({i.prevTx,i.prevOut}); if(it==v.end()) return -1; in+=it->second.value; }
  CAmount o=0; for(auto&x:t.vout) o+=x.value; return in-o;
}
