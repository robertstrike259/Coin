#include "core.h"
#include "hash.h"
#include "ecc.h"
#include <algorithm>
#include <cstring>
std::vector<uint8_t> Transaction::serialize() const {
  SerWriter w; w.u32(version); w.varint(vin.size());
  for(auto&i:vin){ w.bytes(i.prevTx.d.data(),32); w.u32(i.prevOut); w.varint(i.scriptSig.size()); w.bytes(i.scriptSig); w.u32(i.seq); }
  w.varint(vout.size()); for(auto&o:vout){ w.i64(o.value); w.varint(o.pubKeyHash.size()); w.bytes(o.pubKeyHash); }
  w.u32(locktime); return w.v;
}
Transaction Transaction::deserialize(const std::vector<uint8_t>& v){
  if(v.size()>MAX_TX_BYTES) throw std::runtime_error("deserialize: tx too large");
  SerReader r(v); Transaction t; t.version=(int32_t)r.u32(); auto ni=(size_t)r.varintBounded(MAX_TX_INPUTS);
  for(size_t i=0;i<ni;++i){ TxIn in; auto b=r.bytes(32); memcpy(in.prevTx.d.data(),b.data(),32); in.prevOut=r.u32(); auto sl=(size_t)r.varintBounded(MAX_SCRIPT_SIZE); in.scriptSig=r.bytes(sl); in.seq=r.u32(); t.vin.push_back(std::move(in)); }
  auto no=(size_t)r.varintBounded(MAX_TX_OUTPUTS); for(size_t i=0;i<no;++i){ TxOut o; o.value=r.i64(); auto sl=(size_t)r.varintBounded(MAX_SCRIPT_SIZE); o.pubKeyHash=r.bytes(sl); t.vout.push_back(std::move(o)); }
  t.locktime=r.u32(); return t;
}
uint256 Transaction::txid() const { return sha256d(serialize()); }
std::vector<uint8_t> Transaction::sighash() const {
  // Simplified SIGHASH_ALL: serialize with scriptSigs cleared
  Transaction c=*this; for(auto&i:c.vin) i.scriptSig.clear();
  auto s=c.serialize(); auto h=sha256_single(s); return sha256_single(h);
}
std::vector<uint8_t> BlockHeader::serialize() const {
  SerWriter w; w.u32(version); w.bytes(prevHash.d.data(),32); w.bytes(merkleRoot.d.data(),32); w.u32(time); w.u32(bits); w.u32(nonce); return w.v;
}
BlockHeader BlockHeader::deserialize(SerReader& r){
  BlockHeader h; h.version=(int32_t)r.u32(); auto a=r.bytes(32); memcpy(h.prevHash.d.data(),a.data(),32);
  auto b=r.bytes(32); memcpy(h.merkleRoot.d.data(),b.data(),32); h.time=r.u32(); h.bits=r.u32(); h.nonce=r.u32(); return h;
}
uint256 BlockHeader::linkHash() const { return sha256d(serialize()); }
std::vector<uint8_t> BlockHeader::powSalt(const char* net) const {
  std::vector<uint8_t> s(net,net+strlen(net)); s.insert(s.end(),prevHash.d.begin(),prevHash.d.end()); return s;
}
std::vector<uint8_t> Block::serialize() const {
  SerWriter w; auto h=header.serialize(); w.bytes(h); w.varint(txs.size());
  for(auto&t:txs){ auto s=t.serialize(); w.varint(s.size()); w.bytes(s); } return w.v;
}
Block Block::deserialize(const std::vector<uint8_t>& v){
  if(v.size()>MAX_BLOCK_BYTES) throw std::runtime_error("deserialize: block too large");
  SerReader r(v); Block b; b.header=BlockHeader::deserialize(r); auto n=(size_t)r.varintBounded(MAX_TXS_PER_BLOCK);
  for(size_t i=0;i<n;++i){ auto l=(size_t)r.varintBounded(MAX_TX_BYTES); auto tb=r.bytes(l); b.txs.push_back(Transaction::deserialize(tb)); } return b;
}
uint256 merkleRoot(const std::vector<Transaction>& txs){
  if(txs.empty()) return uint256();
  std::vector<uint256> l; for(auto&t:txs) l.push_back(t.txid());
  while(l.size()>1){ std::vector<uint256> n; for(size_t i=0;i<l.size();i+=2){ auto a=l[i], b=l[std::min(i+1,l.size()-1)];
    std::vector<uint8_t> c(a.d.begin(),a.d.end()); c.insert(c.end(),b.d.begin(),b.d.end()); n.push_back(sha256d(c)); } l.swap(n); }
  return l[0];
}
std::vector<uint8_t> hash160_pubkey(const std::vector<uint8_t>& pub33){ return ripemd160(sha256_single(pub33).data(),32); }
static const char* B58="123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
std::string base58Encode(const std::vector<uint8_t>& v){
  std::vector<uint8_t> b(v); int z=0; while(z<(int)b.size()&&b[z]==0)++z;
  std::string s; std::vector<uint8_t> t;
  // repeated divmod 58
  std::vector<int> digits(b.begin(),b.end());
  while(!digits.empty()){ int rem=0; std::vector<int> q; for(int d:digits){ int cur=rem*256+d; q.push_back(cur/58); rem=cur%58; }
    s.push_back(B58[rem]); size_t f=0; while(f<q.size()&&q[f]==0)++f; digits=std::vector<int>(q.begin()+f,q.end()); }
  for(int i=0;i<z;++i)s.push_back('1');
  return {s.rbegin(),s.rend()};
}
static std::vector<uint8_t> b58decode(const std::string& s){
  std::vector<uint8_t> b(1,0);
  for(char c:s){ int v=-1; for(int i=0;B58[i];++i) if(B58[i]==c)v=i; if(v<0) return {};
    int carry=v; for(int i=b.size()-1;i>=0;--i){ int cur=b[i]*58+carry; b[i]=cur&0xff; carry=cur>>8; }
    while(carry){ b.insert(b.begin(),carry&0xff); carry>>=8; } }
  int z=0; for(char c:s){ if(c=='1')++z; else break; }
  std::vector<uint8_t> o(z,0); o.insert(o.end(),b.begin(),b.end()); return o;
}
std::string pubkeyHashToAddress(const std::vector<uint8_t>& h160,uint8_t version){
  std::vector<uint8_t> p; p.push_back(version); p.insert(p.end(),h160.begin(),h160.end());
  auto c=sha256_single(sha256_single(p)); p.insert(p.end(),c.begin(),c.begin()+4); return base58Encode(p);
}
bool addressToHash(const std::string& addr,uint8_t& ver,std::vector<uint8_t>& h160){
  if(addr.size()>64) return false; // DoS cap: valid addresses are ~34 chars
  auto p=b58decode(addr); if(p.size()!=25) return false;
  auto c=sha256_single(sha256_single(std::vector<uint8_t>(p.begin(),p.begin()+21)));
  if(memcmp(c.data(),p.data()+21,4)!=0) return false;
  ver=p[0]; h160={p.begin()+1,p.begin()+21}; return true;
}
