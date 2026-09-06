#include "chain.h"
#include "difficulty.h"
#include "pow.h"
#include "hash.h"
#include <fstream>
#include <filesystem>
#include <ctime>
#include <algorithm>

uint256 Chain::tipHash() const { std::lock_guard<std::mutex> l(m); return idx.empty()?uint256():idx.back().hash; }
int Chain::height() const { std::lock_guard<std::mutex> l(m); return idx.empty()?-1:idx.back().height; }
uint32_t Chain::nextBits() const {
  std::lock_guard<std::mutex> l(m);
  if(idx.empty()) return params.genesisBits;
  if(((int)idx.size()) % (int)params.retargetInterval != 0) return idx.back().bits;
  int from = (int)idx.size() - (int)params.retargetInterval;
  int64_t actual = (int64_t)idx.back().time - (int64_t)idx[from].time;
  int64_t target = (int64_t)params.targetSpacing * params.retargetInterval;
  if(actual < 60) actual = 60;
  return retargetBits(idx.back().bits, actual, target);
}

Block Chain::makeGenesis(){
  Block b; b.header.version=1; b.header.time=(uint32_t)params.genesisTime; b.header.bits=params.genesisBits; b.header.nonce=0;
  Transaction cb; cb.vin.resize(1); cb.vin[0].prevTx=uint256(); cb.vin[0].prevOut=0xffffffff;
  std::string msg="Coin CON genesis - swarf not sats";
  cb.vin[0].scriptSig={msg.begin(),msg.end()};
  cb.vout.push_back({params.genesisReward, std::vector<uint8_t>(20,0)});
  b.txs={cb}; b.header.merkleRoot=merkleRoot(b.txs); return b;
}

namespace {
// Bits expected for a child of `prev` walking that branch (no locks; caller holds).
uint32_t branchBits(const ChainParams& p, const std::map<std::string,BlockIndex>& all, const BlockIndex& prev, int childH){
  if(childH==0) return p.genesisBits;
  if(childH % (int)p.retargetInterval != 0) return prev.bits;
  // walk back interval-1 ancestors from prev to find period start
  BlockIndex cur = prev;
  for(uint32_t i=1;i<p.retargetInterval;++i){
    auto it=all.find(cur.prev.hex());
    if(it==all.end()) return prev.bits; // shouldn't happen; be permissive
    cur=it->second;
  }
  int64_t actual=(int64_t)prev.time-(int64_t)cur.time;
  int64_t target=(int64_t)p.targetSpacing*p.retargetInterval;
  if(actual<60) actual=60;
  return retargetBits(prev.bits,actual,target);
}
// Median of up to 11 ancestor times on the branch ending at prev (incl. prev).
uint32_t branchMedianTime(const std::map<std::string,BlockIndex>& all, const BlockIndex& prev){
  std::vector<uint32_t> v; BlockIndex cur=prev;
  for(int i=0;i<11;++i){ v.push_back(cur.time);
    if(cur.height==0) break;
    auto it=all.find(cur.prev.hex()); if(it==all.end()) break; cur=it->second; }
  std::sort(v.begin(),v.end()); return v[v.size()/2];
}
// Full input validation + fee sum + coinbase check against a UTXO map (no mutation).
bool checkConnect(const ChainParams& p, const Block& b, int h,
                  const std::map<OutPoint,Coin>& view, CAmount& fees, std::string& why){
  for(auto& t:b.txs){ uint256 id=t.txid(); for(uint32_t k=0;k<t.vout.size();++k) if(view.count({id,k})){why="bip30";return false;} }
  fees=0;
  for(size_t i=1;i<b.txs.size();++i){
    auto& t=b.txs[i];
    if(!checkInputs(t,view,why)) return false; // existence, dup, pkh auth, sig
    CAmount f=txFee(t,view); if(f<0){why="missing-utxo";return false;}
    CAmount out=0; for(auto&o:t.vout) out+=o.value;
    fees+=f;
  }
  CAmount expect=blockReward(p,h)+fees;
  CAmount cbv=0; for(auto&o:b.txs[0].vout) cbv+=o.value;
  if(cbv>expect){why="cb-value";return false;}
  return true;
}
// Apply block to a UTXO map, recording undo.
void applyBlock(const Block& b, int h, std::map<OutPoint,Coin>& view, UndoRec& u){
  for(size_t i=1;i<b.txs.size();++i){ auto& t=b.txs[i]; uint256 id=t.txid();
    for(auto&in_:t.vin){ OutPoint o{in_.prevTx,in_.prevOut}; u.spent.push_back({o,view[o]}); view.erase(o); }
    for(uint32_t k=0;k<t.vout.size();++k){ OutPoint o{id,k}; view[o]={t.vout[k].value,t.vout[k].pubKeyHash,h,false}; u.created.push_back(o); } }
  { uint256 id=b.txs[0].txid(); for(uint32_t k=0;k<b.txs[0].vout.size();++k){ OutPoint o{id,k}; view[o]={b.txs[0].vout[k].value,b.txs[0].vout[k].pubKeyHash,h,true}; u.created.push_back(o); } }
}
void unapplyBlock(const UndoRec& u, std::map<OutPoint,Coin>& view){
  for(auto& o:u.created) view.erase(o);
  for(auto& kv:u.spent) view[kv.first]=kv.second;
}
}

bool Chain::acceptBlock(const Block& b,std::string& why,bool& connected){
  connected=false;
  std::lock_guard<std::mutex> l(m);
  uint256 hhash=b.header.linkHash();
  std::string hh=hhash.hex();
  if(allBlocks.count(hh)){why="duplicate";return false;}
  if(invalid.count(hh)){why="invalid-ancestor";return false;}
  // --- header context ---
  int h; BlockIndex prev;
  if(b.header.prevHash.isZero() && idx.empty() && allIndex.empty()){
    h=0;
    if(b.header.bits!=params.genesisBits){why="bad-bits";return false;}
  } else {
    auto it=allIndex.find(b.header.prevHash.hex());
    if(it==allIndex.end()){why="bad-prev";return false;} // orphan (unknown parent)
    prev=it->second;
    // reject branches building on known-invalid blocks
    { BlockIndex c=prev; for(int d=0;d<1024;++d){ if(invalid.count(c.hash.hex())){why="invalid-ancestor";return false;} if(c.height==0)break;
        auto jt=allIndex.find(c.prev.hex()); if(jt==allIndex.end())break; c=jt->second; } }
    h=prev.height+1;
    if(b.header.bits!=branchBits(params,allIndex,prev,h)){why="bad-bits";return false;}
    if(b.header.time<=branchMedianTime(allIndex,prev)){why="bad-time";return false;}
    if((int64_t)b.header.time>(int64_t)time(nullptr)+7200){why="bad-time-future";return false;}
  }
  if(!checkBlock(b,params,h,why)) return false; // structure, merkle, PoW, formats
  // record header+body before connecting (needed for branch walks)
  BlockIndex bi; bi.hash=hhash; bi.prev=b.header.prevHash; bi.height=h; bi.bits=b.header.bits;
  bi.time=b.header.time; bi.nonce=b.header.nonce; bi.merkle=b.header.merkleRoot;
  allIndex[hh]=bi; allBlocks[hh]=b;

  uint256 tip = idx.empty()?uint256():idx.back().hash;
  auto connectTip=[&](const Block& bb,int hhh,std::string& w)->bool{
    CAmount fees=0;
    if(!checkConnect(params,bb,hhh,utxo,fees,w)) return false;
    UndoRec u; applyBlock(bb,hhh,utxo,u);
    undo[bb.header.linkHash().hex()]=std::move(u);
    idx.push_back(bi); byHash[hh]=hhh; blocks.push_back(bb);
    return true;
  };

  if(h==0 || b.header.prevHash==tip){
    if(!connectTip(b,h,why)){ invalid.insert(hh); return false; }
    connected=true;
    return true;
  }
  // --- side branch: only reorg if strictly longer than best ---
  int bestH = idx.empty()?-1:idx.back().height;
  if(h<=bestH) return true; // stored, not connected (shorter fork)
  // find fork point walking back from prev
  std::string forkHex=b.header.prevHash.hex();
  { // fork = highest ancestor of prev that is on best chain
    BlockIndex c=prev;
    while(true){ if(byHash.count(c.hash.hex())){ forkHex=c.hash.hex(); break; }
      if(c.height==0){ forkHex=""; break; }
      auto jt=allIndex.find(c.prev.hex()); if(jt==allIndex.end()){ forkHex=""; break; } c=jt->second; }
  }
  if(forkHex.empty()){why="bad-prev";return false;}
  int forkH=byHash[forkHex];
  // collect side branch blocks from fork+1..h (newest first, then reverse)
  std::vector<Block> side;
  { std::string cur=hh;
    while(cur!=forkHex){
      auto it=allBlocks.find(cur);
      if(it==allBlocks.end()){why="reorg-missing";return false;}
      side.push_back(it->second);
      cur=allIndex[cur].prev.hex();
      if((int)side.size()>h-forkH+2){why="reorg-missing";return false;}
    }
    std::reverse(side.begin(),side.end());
  }
  // scratch validation: copy UTXO, rewind best suffix, apply side
  std::map<OutPoint,Coin> scratch=utxo;
  for(int k=bestH;k>forkH;--k){ auto it=undo.find(idx[k].hash.hex()); if(it==undo.end()){why="reorg-undo";return false;} unapplyBlock(it->second,scratch); }
  std::vector<UndoRec> sideUndos;
  for(size_t i=0;i<side.size();++i){
    int sh=forkH+1+(int)i;
    // height/bits/time context already validated per-block at arrival; re-verify linkage
    CAmount fees=0; std::string w;
    if(!checkConnect(params,side[i],sh,scratch,fees,w)){ why="reorg-invalid:"+w;
      invalid.insert(side[i].header.linkHash().hex()); return false; }
    UndoRec u; applyBlock(side[i],sh,scratch,u); sideUndos.push_back(std::move(u));
  }
  // commit: rewrite best chain from fork
  utxo.swap(scratch);
  idx.resize(forkH+1); blocks.resize(forkH+1);
  // rebuild byHash for truncated suffix
  for(auto it=byHash.begin();it!=byHash.end();){ if(it->second>forkH) it=byHash.erase(it); else ++it; }
  // drop undos of disconnected suffix
  { std::set<std::string> keep; for(auto&x:idx) keep.insert(x.hash.hex());
    for(auto it=undo.begin();it!=undo.end();){ if(!keep.count(it->first)) it=undo.erase(it); else ++it; } }
  for(size_t i=0;i<side.size();++i){
    int sh=forkH+1+(int)i;
    std::string shh=side[i].header.linkHash().hex();
    undo[shh]=std::move(sideUndos[i]);
    idx.push_back(allIndex[shh]); byHash[shh]=sh; blocks.push_back(side[i]);
  }
  connected=true;
  return true;
}

bool Chain::getUtxoSnapshot(std::map<OutPoint,Coin>& o) const { std::lock_guard<std::mutex> l(m); o=utxo; return true; }
bool Chain::getBlock(int h, Block& o) const { std::lock_guard<std::mutex> l(m); if(h<0||h>=(int)blocks.size()) return false; o=blocks[h]; return true; }
bool Chain::getBlockByHash(const uint256& h, Block& o) const {
  std::lock_guard<std::mutex> l(m); auto it=allBlocks.find(h.hex()); if(it==allBlocks.end()) return false; o=it->second; return true;
}

static const uint32_t CHAIN_MAGIC = 0x434F4E31; // "CON1"
bool Chain::save(std::string& err) const {
  std::lock_guard<std::mutex> l(m);
  try{
    std::filesystem::create_directories(datadir);
    SerWriter w; w.u32(CHAIN_MAGIC); w.u32(1); w.u32(blocks.size());
    for(auto&b:blocks){ auto s=b.serialize(); w.u32(s.size()); w.bytes(s); }
    auto body=w.v; auto ck=sha256_single(sha256_single(body));
    body.insert(body.end(),ck.begin(),ck.begin()+8);
    std::string tmp=datadir+"/blocks.dat.tmp";
    { std::ofstream f(tmp,std::ios::binary|std::ios::trunc); if(!f){err="open";return false;}
      f.write((char*)body.data(),body.size()); f.flush(); if(!f){err="write";return false;} }
    std::filesystem::rename(tmp,datadir+"/blocks.dat");
    return true;
  }catch(std::exception& e){err=e.what();return false;}
}
bool Chain::load(std::string& err){
  std::lock_guard<std::mutex> l(m);
  idx.clear();byHash.clear();blocks.clear();utxo.clear();
  allIndex.clear();allBlocks.clear();undo.clear();invalid.clear();
  std::vector<Block> fileBlocks;
  std::ifstream f(datadir+"/blocks.dat",std::ios::binary);
  if(f.good()){
    try{
      std::vector<uint8_t> d((std::istreambuf_iterator<char>(f)),{});
      SerReader r(d);
      // legacy format (no magic) or new format?
      size_t mark=r.off;
      bool isNew=false;
      if(d.size()>=4){ uint32_t mg=r.u32(); if(mg==CHAIN_MAGIC){isNew=true;} else {r.off=mark;} }
      if(isNew){
        uint32_t ver=r.u32(); if(ver!=1){err="version";return false;}
        auto n=r.u32();
        for(uint32_t i=0;i<n;++i){ auto len=r.u32(); auto bb=r.bytes(len); fileBlocks.push_back(Block::deserialize(bb)); }
        if(r.off+8>d.size()){err="truncated";return false;}
        auto ckcalc=sha256_single(sha256_single(std::vector<uint8_t>(d.begin(),d.begin()+r.off)));
        if(memcmp(ckcalc.data(),d.data()+r.off,8)!=0){err="checksum";return false;}
      } else {
        auto n=r.u32();
        for(uint32_t i=0;i<n;++i){ auto len=r.u32(); auto bb=r.bytes(len); fileBlocks.push_back(Block::deserialize(bb)); }
      }
    }catch(std::exception& e){err=std::string("parse: ")+e.what();return false;}
  }
  if(!fileBlocks.empty()){
    // Replay through a scratch Chain (full validation incl. reorg logic), then adopt.
    Chain tmp(params,datadir);
    for(auto&b:fileBlocks){ std::string w; bool c=false; if(!tmp.acceptBlock(b,w,c)){err="replay:"+w;return false;} }
    idx=tmp.idx;byHash=tmp.byHash;blocks=tmp.blocks;utxo=tmp.utxo;
    allIndex=tmp.allIndex;allBlocks=tmp.allBlocks;undo=tmp.undo;
    return true;
  }
  // fresh genesis: mine to valid PoW (easy bits on all nets make this instant)
  Block g=makeGenesis();
  Chain tmp(params,datadir);
  { std::string w;
    for(uint32_t n=0;;++n){ g.header.nonce=n; if(checkPow(g.header,params)) break; if(n>200'000'000){err="genesis-pow";return false;} }
    if(!tmp.acceptBlock(g,w)){err="genesis:"+w;return false;} }
  idx=tmp.idx;byHash=tmp.byHash;blocks=tmp.blocks;utxo=tmp.utxo;
  allIndex=tmp.allIndex;allBlocks=tmp.allBlocks;undo=tmp.undo;
  return true;
}
