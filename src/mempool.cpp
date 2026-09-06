#include "mempool.h"
bool Mempool::add(const Transaction& t,const std::map<OutPoint,Coin>& view,std::string& why){
  if(t.isCoinbase()){why="coinbase";return false;}
  if(!checkTx(t,why)) return false;
  if(!checkInputs(t,view,why)) return false; // existence, dup, pkh auth, sig
  CAmount f=txFee(t,view); if(f<0){why="missing-inputs";return false;} if(f<100){why="minfee";return false;}
  std::lock_guard<std::mutex> l(m);
  for(auto&i:t.vin){ OutPoint o{i.prevTx,i.prevOut};
    auto it=spentBy.find(o);
    if(it!=spentBy.end()&&it->second!=t.txid().hex()){why="mempool-conflict";return false;} }
  std::string id=t.txid().hex();
  txs[id]=t;
  for(auto&i:t.vin) spentBy[{i.prevTx,i.prevOut}]=id;
  return true;
}
std::vector<Transaction> Mempool::templ(){
  std::lock_guard<std::mutex> l(m); std::vector<Transaction> o;
  for(auto&kv:txs) o.push_back(kv.second);
  return o;
}
void Mempool::remove(const std::vector<Transaction>& mined){
  std::lock_guard<std::mutex> l(m);
  for(auto&t:mined){ std::string id=t.txid().hex(); txs.erase(id);
    for(auto&i:t.vin){ auto it=spentBy.find({i.prevTx,i.prevOut}); if(it!=spentBy.end()&&it->second==id) spentBy.erase(it); } }
}
void Mempool::recheck(const std::map<OutPoint,Coin>& view){
  std::lock_guard<std::mutex> l(m);
  std::vector<std::string> drop;
  for(auto&kv:txs){ std::string why; if(!checkInputs(kv.second,view,why)) drop.push_back(kv.first); }
  for(auto&id:drop){ auto it=txs.find(id); if(it==txs.end()) continue;
    for(auto&i:it->second.vin){ auto s=spentBy.find({i.prevTx,i.prevOut}); if(s!=spentBy.end()&&s->second==id) spentBy.erase(s); }
    txs.erase(it); }
}
size_t Mempool::size(){ std::lock_guard<std::mutex> l(m); return txs.size(); }
