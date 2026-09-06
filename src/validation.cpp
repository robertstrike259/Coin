#include "validation.h"
#include "ecc.h"
bool checkTx(const Transaction& t,std::string& why){
  if(t.vin.empty()||t.vout.empty()){why="empty";return false;}
  CAmount o=0; for(auto&x:t.vout){ if(!moneyRange(x.value)){why="value";return false;} o+=x.value; if(!moneyRange(o)){why="overflow";return false;} if(!t.isCoinbase()&&x.pubKeyHash.size()!=20){why="pkh";return false;} }
  if(t.isCoinbase()){ if(t.vin[0].scriptSig.size()>100){why="cb-size";return false;} return true; }
  auto h=t.sighash(); std::vector<uint8_t> hh(h.begin(),h.end());
  for(auto&i:t.vin){ if(i.scriptSig.size()!=97){why="sigsize";return false;}
    std::array<uint8_t,64> sig; memcpy(sig.data(),i.scriptSig.data(),64);
    PubKey pk; memcpy(pk.d.data(),i.scriptSig.data()+64,33);
    if(pk.d[0]!=0x02&&pk.d[0]!=0x03){why="badpubkey";return false;}
    if(!ecc_verify(pk,hh,sig)){why="badsig";return false;} }
  return true;
}
bool checkInputs(const Transaction& t,const std::map<OutPoint,Coin>& view,std::string& why){
  if(t.isCoinbase()){why="coinbase";return false;}
  std::set<std::pair<std::string,uint32_t>> seen;
  auto h=t.sighash(); std::vector<uint8_t> hh(h.begin(),h.end());
  for(auto&i:t.vin){
    OutPoint o{i.prevTx,i.prevOut};
    auto key=std::make_pair(i.prevTx.hex(),i.prevOut);
    if(!seen.insert(key).second){why="dup-input";return false;}
    auto it=view.find(o); if(it==view.end()){why="missing-input";return false;}
    if(i.scriptSig.size()!=97){why="sigsize";return false;}
    std::array<uint8_t,64> sig; memcpy(sig.data(),i.scriptSig.data(),64);
    PubKey pk; memcpy(pk.d.data(),i.scriptSig.data()+64,33);
    if(pk.d[0]!=0x02&&pk.d[0]!=0x03){why="badpubkey";return false;}
    // AUTHORIZATION: signer must own the output being spent
    if(hash160_pubkey({pk.d.begin(),pk.d.end()})!=it->second.pkh){why="pkh-mismatch";return false;}
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
