#include "wallet.h"
#include "hash.h"
#include <fstream>
#include <filesystem>
#include <iterator>
bool Wallet::load(const std::string& file,uint8_t ver){ path=file; addrVersion=ver; keys.clear();
  std::ifstream f(file,std::ios::binary); if(!f.good()) return true;
  try{ std::vector<uint8_t> d((std::istreambuf_iterator<char>(f)),{}); SerReader r(d);
    auto n=(size_t)r.varint(); for(size_t i=0;i<n;++i){ auto a=r.str(); auto skb=r.bytes(32); SecKey k; memcpy(k.d.data(),skb.data(),32); keys[a]=k; } return true;
  }catch(...){return false;} }
bool Wallet::save(const std::string& file) const { std::string p=file.empty()?path:file;
  try{ std::filesystem::create_directories(std::filesystem::path(p).parent_path()); }catch(...){}
  std::ofstream f(p,std::ios::binary|std::ios::trunc); if(!f) return false;
  SerWriter w; w.varint(keys.size()); for(auto&kv:keys){ w.str(kv.first); w.bytes(kv.second.d.data(),32); }
  f.write((char*)w.v.data(),w.v.size()); return true; }
std::string Wallet::newKey(){ SecKey sk=ecc_generate(); PubKey pk; ecc_pubkey(sk,pk);
  auto h=hash160_pubkey({pk.d.begin(),pk.d.end()}); auto a=pubkeyHashToAddress(h,addrVersion); keys[a]=sk; return a; }
bool Wallet::has(const std::string& a) const { return keys.count(a); }
std::vector<std::string> Wallet::addresses() const { std::vector<std::string> o; for(auto&k:keys)o.push_back(k.first); return o; }
Transaction buildSpend(const Wallet& w,const std::map<OutPoint,Coin>& utxo,const std::string& from,const std::string& to,CAmount amount,CAmount fee,uint8_t ver,std::string& why){
  static constexpr CAmount DUST = 1000;
  if(amount<=0){why="bad-amount";return {};}
  if(fee<0){why="bad-fee";return {};}
  uint8_t tv; std::vector<uint8_t> th; if(!addressToHash(to,tv,th)){why="bad-to";return {};} (void)ver;
  auto it=w.keys.find(from); if(it==w.keys.end()){why="no-key";return {};}
  PubKey pk; if(!ecc_pubkey(it->second,pk)){why="no-key";return {};}
  auto fh=hash160_pubkey({pk.d.begin(),pk.d.end()});
  Transaction t; CAmount in=0;
  for(auto&kv:utxo){ if(kv.second.pkh==fh){ TxIn i; i.prevTx=kv.first.tx; i.prevOut=kv.first.n; t.vin.push_back(i); in+=kv.second.value; if(in>=amount+fee)break; } }
  if(in<amount+fee){why="insufficient";return {};}
  TxOut o1{amount,th}; t.vout.push_back(o1);
  CAmount change=in-amount-fee;
  if(change>=DUST) t.vout.push_back({change,fh}); // else: dust folds into fee
  auto h=t.sighash(); std::vector<uint8_t> hh(h.begin(),h.end());
  std::array<uint8_t,64> sig; if(!ecc_sign(it->second,hh,sig)){why="sign";return {};}
  std::vector<uint8_t> ss(sig.begin(),sig.end()); ss.insert(ss.end(),pk.d.begin(),pk.d.end());
  for(auto&i:t.vin) i.scriptSig=ss;
  return t;
}
