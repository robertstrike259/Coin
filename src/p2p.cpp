#include "p2p.h"
#include "hash.h"
#include "validation.h"
#include "platform.h"
#include "net.h"
#include <cstring>
#include <iostream>
std::vector<uint8_t> p2pMsg(const ChainParams& p,const std::string& cmd,const std::vector<uint8_t>& pl){
  SerWriter w; w.u32(p.p2pMagic); char c[12]={0}; memcpy(c,cmd.c_str(),std::min<size_t>(11,cmd.size())); w.bytes((uint8_t*)c,12);
  w.u32(pl.size()); auto ck=sha256_single(sha256_single(pl)); w.bytes(ck.data(),4); w.bytes(pl); return w.v;
}
using tcp = net::tcp;
using Sock = std::shared_ptr<tcp::socket>;
static bool rnexact(tcp::socket& fd,uint8_t*d,size_t n){ return net::read_exact(fd,d,n); }
static bool snexact(tcp::socket& fd,const uint8_t*d,size_t n){ return net::write_all(fd,d,n); }
void P2P::broadcast(const std::string& cmd,const std::vector<uint8_t>& payload,tcp::socket* skip){
  auto m=p2pMsg(chain.params,cmd,payload);
  std::vector<Sock> targets;
  { std::lock_guard<std::mutex> l(liveM); targets.assign(live.begin(),live.end()); }
  for(auto& s:targets){ if(s.get()!=skip) snexact(*s,m.data(),m.size()); }
}
// Shared per-message read with length cap. Returns false on EOF/violation.
static bool readMsg(tcp::socket& c,uint32_t magic,std::string& cmd,std::vector<uint8_t>& pl){
  uint8_t hdr[24]; if(!rnexact(c,hdr,24)) return false;
  SerReader r(hdr,24); uint32_t mg=r.u32(); char cc[13]={0}; auto cb=r.bytes(12); memcpy(cc,cb.data(),12);
  uint32_t len=r.u32(); auto ck=r.bytes(4);
  if(mg!=magic||len>P2P_MAX_MSG) return false;
  pl.assign(len,0); if(len&&!rnexact(c,pl.data(),len)) return false;
  auto ck2=sha256_single(sha256_single(pl)); if(memcmp(ck2.data(),ck.data(),4)) return false;
  cmd=cc; return true;
}
void P2P::start(){
  plt::ignore_sigpipe();
  acceptor=net::listen(io,(uint16_t)port,false);
  if(!acceptor){ std::cerr<<"p2p bind "<<port<<" failed\n"; return; }
  srv=std::thread([this]{
    while(!stop){
      Sock c=std::make_shared<tcp::socket>(io);
      asio::error_code ec; acceptor->accept(*c,ec);
      if(ec){ if(stop)break; continue; }
      { std::lock_guard<std::mutex> l(liveM); live.insert(c); }
      npeers++;
      std::thread th([this,c]{
        std::string cs; std::vector<uint8_t> pl;
        while(!stop){
          if(!readMsg(*c,chain.params.p2pMagic,cs,pl)) break;
          if(cs=="ping"){ auto m=p2pMsg(chain.params,"pong",pl); snexact(*c,m.data(),m.size()); }
          else if(cs=="getheaders"){
            SerWriter w; std::lock_guard<std::mutex> l(chain.m);
            size_t n=std::min<size_t>(chain.blocks.size(),2000);
            w.varint(n); for(size_t i=chain.blocks.size()-n;i<chain.blocks.size();++i){ auto h=chain.blocks[i].header.serialize(); w.bytes(h); }
            auto m=p2pMsg(chain.params,"headers",w.v); snexact(*c,m.data(),m.size());
          }
          else if(cs=="headers"){
            SerReader rr(pl); size_t n=0; try{ n=(size_t)rr.varint(); }catch(...){ break; }
            if(n>2000) break;
            for(size_t i=0;i<n;++i){ BlockHeader h; try{ auto hb=rr.bytes(80); SerReader hr(hb); h=BlockHeader::deserialize(hr); }catch(...){ break; }
              Block b; bool have=false;
              { std::lock_guard<std::mutex> l(chain.m);
                for(auto&bb:chain.blocks) if(bb.header.linkHash()==h.linkHash()){have=true;break;} }
              if(!have){ SerWriter w; auto lh=h.linkHash(); w.bytes(lh.d.data(),32); auto m=p2pMsg(chain.params,"getdata",w.v); snexact(*c,m.data(),m.size()); } }
          }
          else if(cs=="getdata"){ uint256 want; try{ SerReader rr(pl); auto hxb=rr.bytes(32); memcpy(want.d.data(),hxb.data(),32); }catch(...){ break; }
            Block b; if(chain.getBlockByHash(want,b)){ auto m=p2pMsg(chain.params,"block",b.serialize()); snexact(*c,m.data(),m.size()); } }
          else if(cs=="block"){ try{ Block b=Block::deserialize(pl); std::string why; bool conn=false;
              if(chain.acceptBlock(b,why,conn)){ chain.save();
                std::map<OutPoint,Coin> v; chain.getUtxoSnapshot(v); pool.recheck(v,chain.height()+1);
                if(conn){ broadcast("block",b.serialize(),c.get()); if(onBlock)onBlock(b); } } }catch(...){} }
          else if(cs=="tx"){ try{ Transaction t=Transaction::deserialize(pl); std::string why; std::map<OutPoint,Coin> v; chain.getUtxoSnapshot(v);
              if(pool.add(t,v,chain.height()+1,why)) broadcast("tx",t.serialize(),c.get()); }catch(...){} }
          else if(cs=="version"){ auto m=p2pMsg(chain.params,"verack",{}); snexact(*c,m.data(),m.size()); }
        }
        { std::lock_guard<std::mutex> l(liveM); live.erase(c); }
        asio::error_code ec; c->shutdown(tcp::socket::shutdown_both,ec); c->close(ec); npeers--;
      });
      { std::lock_guard<std::mutex> pl(peersM); peers.push_back(std::move(th)); }
    }
  });
}
void P2P::halt(){
  stop=true;
  { std::lock_guard<std::mutex> l(liveM); for(auto& s:live){ asio::error_code ec; s->close(ec); } }
  net::poke((uint16_t)port); // unblock the accept() before joining
  if(acceptor){ asio::error_code ec; acceptor->close(ec); }
  if(srv.joinable())srv.join();
  std::lock_guard<std::mutex> pl(peersM);
  for(auto& t:peers) if(t.joinable())t.join();
  peers.clear();
}
bool P2P::connectPeer(const std::string& host,int p){
  Sock s=std::make_shared<tcp::socket>(io);
  if(!net::connect(io,*s,host,(uint16_t)p)) return false;
  { std::lock_guard<std::mutex> l(liveM); live.insert(s); }
  npeers++;
  auto m=p2pMsg(chain.params,"version",{(uint8_t)1}); snexact(*s,m.data(),m.size());
  auto g=p2pMsg(chain.params,"getheaders",{}); snexact(*s,g.data(),g.size());
  std::thread ot([this,s]{
    std::string cs; std::vector<uint8_t> pl;
    while(!stop){
      if(!readMsg(*s,chain.params.p2pMagic,cs,pl)) break;
      if(cs=="headers"){ SerReader rr(pl); size_t n=0; try{ n=(size_t)rr.varint(); }catch(...){ break; }
        if(n>2000) break;
        for(size_t i=0;i<n;++i){ BlockHeader h; try{ auto hb=rr.bytes(80); SerReader hr(hb); h=BlockHeader::deserialize(hr); }catch(...){ break; }
          bool have=false; { std::lock_guard<std::mutex> l(chain.m); for(auto&b:chain.blocks) if(b.header.linkHash()==h.linkHash()) have=true; }
          if(!have){ SerWriter w; auto lh=h.linkHash(); w.bytes(lh.d.data(),32); auto mm=p2pMsg(chain.params,"getdata",w.v); snexact(*s,mm.data(),mm.size()); } } }
      else if(cs=="getdata"){ uint256 want; try{ SerReader rr(pl); auto hxb=rr.bytes(32); memcpy(want.d.data(),hxb.data(),32); }catch(...){ break; }
        Block b; if(chain.getBlockByHash(want,b)){ auto mm=p2pMsg(chain.params,"block",b.serialize()); snexact(*s,mm.data(),mm.size()); } }
      else if(cs=="block"){ try{ Block b=Block::deserialize(pl); std::string why; bool conn=false;
          if(chain.acceptBlock(b,why,conn)){ chain.save();
            std::map<OutPoint,Coin> v; chain.getUtxoSnapshot(v); pool.recheck(v,chain.height()+1);
            if(conn){ broadcast("block",b.serialize(),s.get()); if(onBlock)onBlock(b); } } }catch(...){} }
      else if(cs=="tx"){ try{ Transaction t=Transaction::deserialize(pl); std::string why; std::map<OutPoint,Coin> v; chain.getUtxoSnapshot(v);
          if(pool.add(t,v,chain.height()+1,why)) broadcast("tx",t.serialize(),s.get()); }catch(...){} }
      else if(cs=="pong"){}
      else if(cs=="verack"){}
      else if(cs=="ping"){ auto mm=p2pMsg(chain.params,"pong",pl); snexact(*s,mm.data(),mm.size()); }
    }
    { std::lock_guard<std::mutex> l(liveM); live.erase(s); }
    asio::error_code ec; s->shutdown(tcp::socket::shutdown_both,ec); s->close(ec); npeers--;
  });
  { std::lock_guard<std::mutex> pl(peersM); peers.push_back(std::move(ot)); }
  return true;
}
