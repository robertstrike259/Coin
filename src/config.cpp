#include "config.h"
#include "platform.h"
#include <iostream>
std::string expandHome(const std::string& s){ return plt::expand_home(s); }
static std::string argval(int argc,char**argv,const std::string& k,std::string d=""){
  for(int i=1;i<argc;++i){ std::string a=argv[i]; if(a==k&&i+1<argc) return argv[i+1]; if(a.rfind(k+"=",0)==0) return a.substr(k.size()+1); } return d;
}
static bool hasflag(int argc,char**argv,const std::string& k){ for(int i=1;i<argc;++i) if(argv[i]==k) return true; return false; }
static int safeStoi(const std::string& s,int dflt,const char* what){
  try{ size_t p=0; int v=std::stoi(s,&p); if(p!=s.size()) throw std::runtime_error("trailing"); return v; }
  catch(...){ std::cerr<<"warning: bad "<<what<<" '"<<s<<"', using "<<dflt<<"\n"; return dflt; }
}
Config parseArgs(int argc,char**argv,const char* app){
  Config c;
  c.net=argval(argc,argv,"--net",argval(argc,argv,"--network","regtest"));
  if(hasflag(argc,argv,"--mainnet"))c.net="main"; if(hasflag(argc,argv,"--testnet"))c.net="testnet"; if(hasflag(argc,argv,"--regtest"))c.net="regtest";
  ChainParams d = c.net=="main"?mainParams():c.net=="testnet"?testParams():regtestParams();
  c.datadir=plt::expand_home(argval(argc,argv,"--datadir",plt::default_datadir(c.net)));
  c.port=safeStoi(argval(argc,argv,"--port",std::to_string(d.defaultPort)),d.defaultPort,"--port");
  c.rpcport=safeStoi(argval(argc,argv,"--rpcport",std::to_string(d.rpcPort)),d.rpcPort,"--rpcport");
  c.miningAddress=argval(argc,argv,"--mining-address",argval(argc,argv,"--address",""));
  c.threads=safeStoi(argval(argc,argv,"--threads","1"),1,"--threads");
  if(c.threads<1)c.threads=1; if(c.threads>1024)c.threads=1024;
  (void)app; return c;
}
