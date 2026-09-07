#include "config.h"
#include "wallet.h"
#include "rpc.h"
#include "platform.h"
#include <nlohmann/json.hpp>
#include <openssl/crypto.h>
#include <iostream>
#include <fstream>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <string>
#include <tuple>
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
static std::string argval(int argc,char**argv,const std::string& k){
  for(int i=1;i<argc;++i){ std::string a=argv[i];
    if(a==k&&i+1<argc) return argv[i+1];
    if(a.rfind(k+"=",0)==0) return a.substr(k.size()+1); }
  return "";
}
// Password source: --password-file PATH (first line), else secure prompt.
// Single heap allocation, cleansed on destroy; no std::string copies.
static SecureString getPassword(int argc,char**argv,const std::string& flag,const std::string& prompt){
  SecureString pw;
  std::string f=argval(argc,argv,flag);
  if(!f.empty()){
    std::ifstream in(f,std::ios::binary);
    char buf[1024]; size_t n=0;
    if(in){ int c; while(n<sizeof buf&&(c=in.get())!=EOF&&c!='\n'&&c!='\r'){ buf[n++]=(char)c; } }
    if(n==0){ std::cout<<"cannot read "<<flag<<" "<<f<<"\n"; }
    else { pw.assign(buf,n); }
    OPENSSL_cleanse(buf,sizeof buf);
    return pw;
  }
  std::string shown=plt::read_password(prompt); // echoed-off TTY input (short-lived)
  pw.assign(shown.data(),shown.size());
  OPENSSL_cleanse(shown.data(),shown.size());
  return pw;
}
int main(int argc,char**argv){
  if(argc<2){ std::cout<<"coin-wallet [--datadir D --net N --rpcport P --password-file F] newkey|addresses|balance ADDR|send FROM TO CON_AMOUNT|encrypt|changepass\n"; return 0; }
  Config c=parseArgs(argc,argv,"coin-wallet");
  for(int i=1;i<argc;++i){ std::string a=argv[i]; if(a=="--rpcport"&&i+1<argc){ try{c.rpcport=std::stoi(argv[++i]);}catch(...){} } }
  std::string wfile=c.datadir+"/wallet.dat";
  std::string cmd;
  for(int i=1;i<argc;++i){ std::string a=argv[i];
    if(a=="newkey"||a=="addresses"||a=="send"||a=="balance"||a=="encrypt"||a=="changepass"){ cmd=a; break; }
  }
  if(cmd=="encrypt"){ // migrate legacy plaintext -> encrypted (or re-encrypt)
    Wallet w; if(!w.load(wfile,c.params().addrVersion)){ std::cout<<"cannot read wallet (wrong state?)\n"; return 1; }
    if(w.encrypted){ std::cout<<"already encrypted; use changepass to rotate\n"; return 1; }
    SecureString pw=getPassword(argc,argv,"--password-file","New wallet password: ");
    if(pw.empty()){ std::cout<<"empty password refused\n"; return 1; }
    bool ok=w.save(wfile,pw); pw.clear();
    std::cout<<(ok?"encrypted\n":"encrypt failed\n"); return ok?0:1;
  }
  if(cmd=="changepass"){
    std::string npf=argval(argc,argv,"--new-password-file");
    if(npf.empty()){ std::cout<<"need --new-password-file\n"; return 1; }
    SecureString pw=getPassword(argc,argv,"--password-file","Current wallet password: ");
    Wallet w; if(!w.load(wfile,c.params().addrVersion,pw)){ pw.clear(); std::cout<<"decrypt failed (wrong password?)\n"; return 1; }
    pw.clear();
    char nbuf[1024]; size_t nn=0;
    { std::ifstream in(npf,std::ios::binary); int c; while(nn<sizeof nbuf&&(c=in.get())!=EOF&&c!='\n'&&c!='\r'){ nbuf[nn++]=(char)c; } }
    SecureString npw; npw.assign(nbuf,nn); OPENSSL_cleanse(nbuf,sizeof nbuf);
    if(nn==0){ std::cout<<"cannot read new password file\n"; return 1; }
    if(npw.empty()){ std::cout<<"empty password refused\n"; return 1; }
    bool ok=w.save(wfile,npw); npw.clear();
    std::cout<<(ok?"password changed\n":"change failed\n"); return ok?0:1;
  }
  SecureString pw=getPassword(argc,argv,"--password-file","Wallet password: ");
  Wallet w; if(!w.load(wfile,c.params().addrVersion,pw)){
    // Legacy plaintext loads without password; encrypted needs it.
    Wallet probe; bool legacy=false;
    { std::ifstream f(wfile,std::ios::binary); char mg[4]={0}; f.read(mg,4);
      legacy = !f.good() || memcmp(mg,"CONW",4)!=0; }
    pw.clear();
    if(legacy){ std::cout<<"wallet is plaintext legacy: run 'encrypt' first\n"; }
    else std::cout<<"decrypt failed (wrong password or corrupt wallet)\n";
    return 1;
  }
  int rc=0;
  if(cmd=="newkey"){ auto a=w.newKey(); if(!w.save(wfile,pw)) { std::cout<<"save failed\n"; rc=1; } else std::cout<<a<<"\n"; }
  else if(cmd=="addresses"){ for(auto&a:w.addresses()) std::cout<<a<<"\n"; }
  else if(cmd=="balance"){
    std::string addr; for(int i=1;i<argc;++i){ if(std::string(argv[i])=="balance"&&i+1<argc){addr=argv[i+1];break;} }
    std::cout<<rpcCall(c.rpcport,"getbalance","{\"address\":\""+addr+"\"}")<<"\n";
  }
  else if(cmd=="send"){ // send FROM TO CONs
    std::string from, to; double amt=0;
    for(int i=1;i<argc;++i){ if(std::string(argv[i])=="send"&&i+3<argc){ from=argv[i+1]; to=argv[i+2]; amt=atof(argv[i+3]); break; } }
    if(!(amt>0)){ std::cout<<"amount must be positive\n"; rc=1; }
    else{
      CAmount swarf=(CAmount)(amt*100000000.0+0.5), fee=1000;
      if(swarf<=0){ std::cout<<"amount too small\n"; rc=1; }
      else if(!w.has(from)){ std::cout<<"no key for "<<from<<"\n"; rc=1; }
      else{
        auto uj=rpcCall(c.rpcport,"listunspent","{\"address\":\""+from+"\"}");
        std::vector<std::tuple<std::string,uint32_t,CAmount,int>> u; parseUnspent(uj,u);
        if(u.empty()){ std::cout<<"no unspent for "<<from<<": "<<uj<<"\n"; rc=1; }
        else{
          std::map<OutPoint,Coin> view;
          { PubKey pk; auto it=w.keys.find(from); ecc_pubkey(it->second,pk);
            auto fh=hash160_pubkey({pk.d.begin(),pk.d.end()});
            for(auto&e:u){ OutPoint o{uint256::fromHex(std::get<0>(e)),std::get<1>(e)}; view[o]={std::get<2>(e),fh,std::get<3>(e),false}; } }
          std::string why; Transaction t=buildSpend(w,view,from,to,swarf,fee,c.params().addrVersion,why);
          if(t.vin.empty()){ std::cout<<"build failed: "<<why<<"\n"; rc=1; }
          else std::cout<<rpcCall(c.rpcport,"sendrawtransaction","{\"hex\":\""+hexof(t.serialize())+"\"}")<<"\n";
        }
      }
    }
  }
  else{ std::cout<<"unknown cmd\n"; rc=1; }
  pw.clear();
  return rc;
}
