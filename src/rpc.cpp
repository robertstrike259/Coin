#include "rpc.h"
#include "hash.h"
#include "platform.h"
#include "net.h"
#include <nlohmann/json.hpp>
#include <algorithm>
#include <sstream>
#include <iostream>
#include <cstring>
#include <cstdlib>
#include <ctime>
using nlohmann::json;
static std::string hexv(const std::vector<uint8_t>& v){ static const char*h="0123456789abcdef"; std::string s; for(auto b:v){s.push_back(h[b>>4]);s.push_back(h[b&15]);} return s; }
static std::vector<uint8_t> unhex(const std::string& s){ std::vector<uint8_t> o; for(size_t i=0;i+1<s.size();i+=2){ o.push_back((uint8_t)strtoul(s.substr(i,2).c_str(),nullptr,16)); } return o; }
static std::string handle(RpcServer& self,const std::string& method,const json& params){
  Chain& chain=self.chain; Mempool& pool=self.pool; const std::string& miningAddr=self.miningAddr;
  if(method=="getblockchaininfo"){ json j; j["chain"]=chain.params.name; j["height"]=chain.height(); j["tip"]=chain.tipHash().hex(); j["mempool"]=pool.size(); return j.dump(); }
  if(method=="getpeerinfo"){ json j; j["peers"]=self.peerCount?self.peerCount():0; return j.dump(); }
  if(method=="getblocktemplate"){
    Block t; t.header.version=1; t.header.prevHash=chain.tipHash();
    // Consensus requires time > median-past; floor at tip+1 so back-to-back
    // templates in the same second stay valid (regtest mines instantly).
    uint32_t now=(uint32_t)time(nullptr), tt=chain.tipTime();
    t.header.time = now>tt ? now : tt+1;
    t.header.bits=chain.nextBits();
    int nh = chain.height()+1;
    Transaction cb; cb.vin.resize(1); std::string tag="mined by CON";
    for(int i=0;i<4;++i) tag.push_back((nh>>(8*i))&0xff);
    uint32_t tm=t.header.time; for(int i=0;i<4;++i) tag.push_back((tm>>(8*i))&0xff);
    cb.vin[0].scriptSig={tag.begin(),tag.end()};
    uint8_t ver; std::vector<uint8_t> h160;
    if(!miningAddr.empty()&&addressToHash(miningAddr,ver,h160)) cb.vout.push_back({blockReward(chain.params,nh),h160});
    else cb.vout.push_back({blockReward(chain.params,nh),std::vector<uint8_t>(20,0)});
    auto mem=pool.templ(); t.txs.push_back(cb); for(auto&x:mem) t.txs.push_back(x);
    t.header.merkleRoot=merkleRoot(t.txs);
    json j; j["template_hex"]=hexv(t.serialize()); j["height"]=nh; j["bits"]=t.header.bits; return j.dump();
  }
  if(method=="submitblock"){
    if(!params.contains("hex")) return "{\"error\":\"no hex\"}";
    try{
      std::string hex=params["hex"].get<std::string>();
      if(hex.size()>MAX_RPC_HEX){ json j; j["error"]="too-large"; return j.dump(); }
      Block blk=Block::deserialize(unhex(hex));
      std::string why; bool conn=false;
      if(!chain.acceptBlock(blk,why,conn)){ json j; j["error"]=why; return j.dump(); }
      chain.save();
      if(conn){ // only confirmed-tip txs leave the mempool; revalidate the rest
        pool.remove(blk.txs);
        std::map<OutPoint,Coin> v; chain.getUtxoSnapshot(v); pool.recheck(v,chain.height()+1);
        if(self.onBlockAccepted) self.onBlockAccepted(blk);
      }
      json j; j["ok"]=true; j["connected"]=conn; return j.dump();
    }catch(std::exception& e){ json j; j["error"]=std::string("parse: ")+e.what(); return j.dump(); }
  }
  if(method=="sendrawtransaction"){
    if(!params.contains("hex")) return "{\"error\":\"no hex\"}";
    try{
      std::string hex=params["hex"].get<std::string>();
      if(hex.size()>MAX_RPC_HEX){ json j; j["error"]="too-large"; return j.dump(); }
      auto tx=Transaction::deserialize(unhex(hex));
      std::string why; std::map<OutPoint,Coin> v; chain.getUtxoSnapshot(v);
      if(!pool.add(tx,v,chain.height()+1,why)){ json j; j["error"]=why; return j.dump(); }
      if(self.onTxAccepted) self.onTxAccepted(tx);
      json j; j["txid"]=tx.txid().hex(); return j.dump();
    }catch(std::exception& e){ json j; j["error"]=std::string("parse: ")+e.what(); return j.dump(); }
  }
  if(method=="listunspent"||method=="getbalance"){
    if(!params.contains("address")) return "{\"error\":\"no address\"}";
    std::string addr=params["address"].get<std::string>();
    uint8_t ver; std::vector<uint8_t> h160; if(!addressToHash(addr,ver,h160)) return "{\"error\":\"bad-address\"}";
    std::map<OutPoint,Coin> v; chain.getUtxoSnapshot(v);
    CAmount bal=0; json arr=json::array();
    for(auto&kv:v){ if(kv.second.pkh==h160){ bal+=kv.second.value;
      if(method=="listunspent") arr.push_back({{"txid",kv.first.tx.hex()},{"vout",kv.first.n},{"value_swarf",kv.second.value},{"height",kv.second.height},{"coinbase",kv.second.coinbase}}); } }
    if(method=="listunspent"){ json j; j["unspent"]=arr; return j.dump(); }
    json j; j["balance_swarf"]=bal; return j.dump();
  }
  return "{\"error\":\"unknown\"}";
}
void RpcServer::start(){
  plt::ignore_sigpipe();
  th=std::thread([this]{
    auto acc=net::listen(io,(uint16_t)port,true); // loopback only
    if(!acc){ std::cerr<<"rpc bind "<<port<<" failed\n"; return; }
    acceptor=std::move(acc);
    while(!stop){
      net::tcp::socket c(io);
      asio::error_code ec; acceptor->accept(c,ec);
      if(ec){ if(stop)break; continue; }
      // read headers + body (requests are small; single read loop to blank line)
      std::string req; char buf[4096];
      for(;;){ size_t r=0; { asio::error_code e2; r=asio::read(c,asio::buffer(buf,sizeof buf-1),asio::transfer_at_least(1),e2); if(e2) break; }
        buf[r]=0; req.append(buf,r); if(req.find("\r\n\r\n")!=std::string::npos) break; if(req.size()>65536) break; }
      // honor Content-Length: keep reading until the full body arrives
      auto clen=[&]()->size_t{ auto p=req.find("Content-Length:"); if(p==std::string::npos) return 0;
        return (size_t)strtoul(req.c_str()+p+15,nullptr,10); };
      { auto bodypos=req.find("\r\n\r\n"); size_t have=bodypos==std::string::npos?0:req.size()-bodypos-4;
        size_t want=clen();
        while(have<want&&req.size()<1048576){ char b2[4096]; asio::error_code e2;
          size_t r=asio::read(c,asio::buffer(b2,std::min<size_t>(sizeof b2,want-have)),asio::transfer_at_least(1),e2);
          if(e2||r==0) break; req.append(b2,r); have+=r; } }
      if(!req.empty()){
        std::string method; json prm=json::object();
        try{
          auto bodypos=req.find("\r\n\r\n"); std::string jb=bodypos==std::string::npos?req:req.substr(bodypos+4);
          auto j=json::parse(jb); method=j.value("method",""); prm=j.value("params",json::object());
        }catch(...){}
        std::string body=handle(*this,method,prm);
        std::ostringstream o; o<<"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "<<body.size()<<"\r\nConnection: close\r\n\r\n"<<body;
        auto so=o.str(); net::write_all(c,(const uint8_t*)so.data(),so.size());
      }
      asio::error_code ec2; c.shutdown(net::tcp::socket::shutdown_both,ec2); c.close(ec2);
    }
  });
}
void RpcServer::halt(){ stop=true;
  net::poke((uint16_t)port); // unblock the accept() before joining
  if(acceptor){ asio::error_code ec; acceptor->close(ec); }
  if(th.joinable())th.join(); }
std::string rpcCall(int port,const std::string& method,const std::string& paramsJson){
  try{
    asio::io_context io; net::tcp::socket s(io);
    if(!net::connect(io,s,"127.0.0.1",(uint16_t)port)) return "{\"error\":\"connect\"}";
    std::string body="{\"method\":\""+method+"\",\"params\":"+paramsJson+"}";
    std::ostringstream o; o<<"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: "<<body.size()<<"\r\nConnection: close\r\n\r\n"<<body;
    auto q=o.str(); if(!net::write_all(s,(const uint8_t*)q.data(),q.size())) return "{\"error\":\"connect\"}";
    std::string resp; char b[4096]; asio::error_code ec;
    while(!ec){ size_t r=asio::read(s,asio::buffer(b,sizeof b),asio::transfer_at_least(1),ec); if(r) resp.append(b,r); }
    auto f=resp.find("\r\n\r\n"); return f==std::string::npos?resp:resp.substr(f+4);
  }catch(...){ return "{\"error\":\"connect\"}"; }
}
