#include "config.h"
#include "wallet.h"
#include "rpc.h"
#include <nlohmann/json.hpp>
#include <iostream>
#include <cctype>
static std::vector<uint8_t> unhex(const std::string& s){ std::vector<uint8_t> o; for(size_t i=0;i+1<s.size();i+=2) o.push_back(strtoul(s.substr(i,2).c_str(),nullptr,16)); return o; }
static std::string hexof(const std::vector<uint8_t>& v){ static const char*h="0123456789abcdef"; std::string s; for(auto b:v){s.push_back(h[b>>4]);s.push_back(h[b&15]);} return s; }
// unspent entries from listunspent: {txid, vout, value_swarf, height}
static void parseUnspent(const std::string& js, std::vector<std::tuple<std::string,uint32_t,CAmount,int>>& out){
  try{
    auto j=nlohmann::json::parse(js);
    for(auto&e:j.value("unspent",nlohmann::json::array()))
      out.emplace_back(e["txid"].get<std::string>(),e["vout"].get<uint32_t>(),e["value_swarf"].get<CAmount>(),e["height"].get<int>());
  }catch(...){}
}
int main(int argc,char**argv){
  if(argc<2){ std::cout<<"coin-wallet [--datadir D --net N --rpcport P] newkey|addresses|balance ADDR|send FROM TO CON_AMOUNT\n"; return 0; }
  Config c=parseArgs(argc,argv,"coin-wallet");
  for(int i=1;i<argc;++i){ std::string a=argv[i]; if(a=="--rpcport"&&i+1<argc) c.rpcport=std::stoi(argv[++i]); }
  Wallet w; if(!w.load(c.datadir+"/wallet.dat", c.params().addrVersion)){ std::cout<<"wallet.dat corrupt, refusing to touch it\n"; return 1; }
  std::string cmd;
  for(int i=1;i<argc;++i){ std::string a=argv[i];
    if(a=="newkey"||a=="addresses"||a=="send"||a=="balance"){ cmd=a; break; }
  }
  if(cmd=="newkey"){ auto a=w.newKey(); w.save(); std::cout<<a<<"\n"; }
  else if(cmd=="addresses"){ for(auto&a:w.addresses()) std::cout<<a<<"\n"; }
  else if(cmd=="balance"){
    std::string addr; for(int i=1;i<argc;++i){ if(std::string(argv[i])=="balance"&&i+1<argc){addr=argv[i+1];break;} }
    std::cout<<rpcCall(c.rpcport,"getbalance","{\"address\":\""+addr+"\"}")<<"\n";
  }
  else if(cmd=="send"){ // send FROM TO CONs
    std::string from, to; double amt=0;
    for(int i=1;i<argc;++i){ if(std::string(argv[i])=="send"&&i+3<argc){ from=argv[i+1]; to=argv[i+2]; amt=atof(argv[i+3]); break; } }
    if(!(amt>0)){ std::cout<<"amount must be positive\n"; return 1; }
    CAmount swarf=(CAmount)(amt*100000000.0+0.5), fee=1000;
    if(swarf<=0){ std::cout<<"amount too small\n"; return 1; }
    if(!w.has(from)){ std::cout<<"no key for "<<from<<"\n"; return 1; }
    auto uj=rpcCall(c.rpcport,"listunspent","{\"address\":\""+from+"\"}");
    std::vector<std::tuple<std::string,uint32_t,CAmount,int>> u; parseUnspent(uj,u);
    if(u.empty()){ std::cout<<"no unspent for "<<from<<": "<<uj<<"\n"; return 1; }
    std::map<OutPoint,Coin> view;
    uint8_t vv; std::vector<uint8_t> fh;
    { PubKey pk; auto it=w.keys.find(from); ecc_pubkey(it->second,pk); fh=hash160_pubkey({pk.d.begin(),pk.d.end()}); }
    for(auto&e:u){ OutPoint o{uint256::fromHex(std::get<0>(e)),std::get<1>(e)}; view[o]={std::get<2>(e),fh,std::get<3>(e),false}; }
    std::string why; Transaction t=buildSpend(w,view,from,to,swarf,fee,c.params().addrVersion,why);
    if(t.vin.empty()){ std::cout<<"build failed: "<<why<<"\n"; return 1; }
    std::cout<<rpcCall(c.rpcport,"sendrawtransaction","{\"hex\":\""+hexof(t.serialize())+"\"}")<<"\n";
  }
  else std::cout<<"unknown cmd\n";
  return 0;
}
