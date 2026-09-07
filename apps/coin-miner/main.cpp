#include "rpc.h"
#include "core.h"
#include "ecc.h"
#include "pow.h"
#include "difficulty.h"
#include "platform.h"
#include "chainparams.h"
#include <argon2.h>
#include <nlohmann/json.hpp>
#include <iostream>
#include <thread>
#include <atomic>
#include <ctime>
#include <cstring>
#include <cstdlib>
#include <string>
#include <algorithm>
static std::vector<uint8_t> unhex(const std::string& s){ std::vector<uint8_t> o; for(size_t i=0;i+1<s.size();i+=2) o.push_back(strtoul(s.substr(i,2).c_str(),nullptr,16)); return o; }
int main(int argc,char**argv){
  int rpcport=19443, threads=1, nblocks=1; std::string addr, net="regtest";
  auto num=[&](const std::string& s,int d){ try{ return std::stoi(s); }catch(...){ return d; } };
  for(int i=1;i<argc;++i){ std::string a=argv[i];
    if(a=="--help"){ std::cout<<"coin-miner [--net main|testnet|regtest] --rpcport P --address ADDR --threads N --blocks N\n"; return 0; }
    if(a=="--net"&&i+1<argc)net=argv[++i];
    if(a=="--mainnet")net="main"; if(a=="--testnet")net="testnet"; if(a=="--regtest")net="regtest";
    if(a=="--rpcport"&&i+1<argc)rpcport=num(argv[++i],rpcport);
    if(a=="--threads"&&i+1<argc)threads=std::max(1,num(argv[++i],threads));
    if(a=="--blocks"&&i+1<argc)nblocks=std::max(1,num(argv[++i],nblocks));
    if((a=="--address"||a=="--mining-address")&&i+1<argc)addr=argv[++i]; }
  { std::string e; if(!ecc_init(e)){ std::cout<<"fatal: "<<e<<"\n"; return 1; } }
  ChainParams p = net=="main"?mainParams():net=="testnet"?testParams():regtestParams();
  for(int b=0;b<nblocks;++b){
    bool done=false;
    for(int attempt=0;attempt<10&&!done;++attempt){
    if(attempt>0) plt::sleep_ms(1100); // let clock/template advance past a reject
    nlohmann::json tj;
    try { tj=nlohmann::json::parse(rpcCall(rpcport,"getblocktemplate","{}")); }
    catch(...){ std::cout<<"no template (bad rpc)\n"; continue; }
    if(!tj.contains("template_hex")){ std::cout<<"no template: "<<tj.dump()<<"\n"; continue; }
    Block t;
    try { t=Block::deserialize(unhex(tj["template_hex"].get<std::string>())); }
    catch(std::exception& e){ std::cout<<"bad template: "<<e.what()<<"\n"; continue; }
    // set mining payout if --address given: rebuild coinbase
    if(!addr.empty()){ uint8_t v; std::vector<uint8_t> h; if(addressToHash(addr,v,h)){ t.txs[0].vout[0].pubKeyHash=h; } }
    // extraNonce: random suffix guarantees unique coinbase even across miners on same template.
    // Uniqueness (not secrecy) is what matters, so fall back to time-seeded
    // bytes if the CSPRNG ever fails rather than mining a duplicate txid.
    { uint8_t r[4];
      if(!plt::random_bytes(r,4)){ uint32_t f=(uint32_t)time(nullptr)^(uint32_t)clock()^((uint32_t)plt::process_id()<<5); memcpy(r,&f,4); }
      for(int i=0;i<4;++i) t.txs[0].vin[0].scriptSig.push_back(r[i]);
      t.header.merkleRoot=merkleRoot(t.txs); }
    std::atomic<bool> found=false; std::atomic<uint32_t> fnonce=0;
    auto worker=[&](int id){
      BlockHeader h=t.header;
      for(uint32_t n=id;!found;n+=threads){ h.nonce=n;
        // never go below the template time (it already encodes the tip+1 floor)
        uint32_t now=(uint32_t)time(nullptr); h.time=now>t.header.time?now:t.header.time;
        auto hdr=h.serialize(); auto salt=h.powSalt(p.name);
        uint8_t out[32];
        if(argon2id_hash_raw(p.argonPasses,p.argonMemKib,1,hdr.data(),hdr.size(),salt.data(),salt.size(),out,sizeof out)!=ARGON2_OK) return;
        uint256 u; memcpy(u.d.data(),out,32);
        if(hashMeetsBits(u,h.bits)){ if(!found.exchange(true)){ fnonce=n; t.header=h; } return; }
        if(n%2000==0&&found) return;
      }
    };
    std::vector<std::thread> th; for(int i=0;i<threads;++i) th.emplace_back(worker,i); for(auto&t2:th)t2.join();
    t.header.nonce=fnonce;
    auto s=t.serialize(); static const char*h="0123456789abcdef"; std::string hx; for(auto c:s){hx.push_back(h[c>>4]);hx.push_back(h[c&15]);}
    std::string res=rpcCall(rpcport,"submitblock","{\"hex\":\""+hx+"\"}");
    std::cout<<"mined block h~ nonce="<<fnonce<<" txs="<<t.txs.size()<<"\n"<<res<<"\n";
    if(res.find("\"ok\"")!=std::string::npos){ done=true; }
    else std::cout<<"submit rejected, retrying with fresh template\n";
    } // attempts
    if(!done){ std::cout<<"gave up on block "<<b<<"\n"; return 1; }
  }
  return 0;
}
