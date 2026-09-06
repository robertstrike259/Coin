#include "config.h"
#include "chain.h"
#include "mempool.h"
#include "p2p.h"
#include "rpc.h"
#include "platform.h"
#include <iostream>
#include <csignal>
#include <filesystem>
static bool gStop=false;
int main(int argc,char**argv){
  for(int i=1;i<argc;++i){ std::string a=argv[i]; if(a=="--help"||a=="-h"){ std::cout<<"coind - Coin (CON) node daemon\n--datadir --net main|testnet|regtest --port --rpcport --mining-address ADDR --peer HOST:PORT\n"; return 0; } }
  Config c=parseArgs(argc,argv,"coind");
  if(!c.miningAddress.empty()){ uint8_t v; std::vector<uint8_t> h;
    if(!addressToHash(c.miningAddress,v,h)) std::cerr<<"warning: --mining-address is not a valid address; templates will pay burn output\n"; }
  Chain chain(c.params(),c.datadir); Mempool pool;
  { std::string err;
    if(!chain.load(err)){
      // Never silently wipe: move a corrupt file aside, refuse only if unrecoverable state
      std::string bad=c.datadir+"/blocks.dat";
      if(std::filesystem::exists(bad)&&err!=""){
        std::cerr<<"chain load failed ("<<err<<"); archiving corrupt file and starting fresh\n";
        std::error_code ec; std::filesystem::rename(bad,bad+".corrupt",ec);
        if(!chain.load(err)){ std::cerr<<"fatal: "<<err<<"\n"; return 1; }
      } else { std::cerr<<"fatal: "<<err<<"\n"; return 1; }
    } }
  std::cout<<"Coin coind v0.1.0 net="<<c.net<<" height="<<chain.height()<<" tip="<<chain.tipHash().hex()<<"\n";
  P2P net(chain,pool,c.port); net.start();
  RpcServer rpc(chain,pool,c.rpcport); rpc.miningAddr=c.miningAddress;
  rpc.onBlockAccepted=[&](const Block& b){ net.broadcast("block",b.serialize()); };
  rpc.onTxAccepted=[&](const Transaction& t){ net.broadcast("tx",t.serialize()); };
  rpc.peerCount=[&]()->size_t{ return net.peerCount(); };
  rpc.start();
  for(int i=1;i<argc;++i){ std::string a=argv[i]; if(a=="--peer"&&i+1<argc){ std::string hp=argv[++i];
    auto f=hp.find(":"); std::string host=(f==std::string::npos)?hp:hp.substr(0,f);
    int pport=0; try{ pport=std::stoi(f==std::string::npos?"":hp.substr(f+1)); }catch(...){}
    if(host.empty()||pport<=0||pport>65535){ std::cerr<<"bad --peer (want HOST:PORT): "<<hp<<"\n"; continue; }
    if(!net.connectPeer(host,pport)) std::cerr<<"peer connect failed: "<<hp<<"\n"; } }
  std::cout<<"P2P:"<<c.port<<" RPC:"<<c.rpcport<<" datadir="<<c.datadir<<"\nPress Ctrl-C to stop.\n";
  signal(SIGINT,[](int){gStop=true;}); signal(SIGTERM,[](int){gStop=true;});
  while(!gStop) plt::sleep_sec(1);
  net.halt(); rpc.halt();
  { std::string err; if(!chain.save(err)) std::cerr<<"save failed: "<<err<<"\n"; }
  return 0;
}
