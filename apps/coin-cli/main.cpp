#include "rpc.h"
#include <iostream>
#include <string>
int main(int argc,char**argv){
  int rpcport=19443; std::string method="getblockchaininfo", params="{}";
  for(int i=1;i<argc;++i){ std::string a=argv[i];
    if(a=="--rpcport"&&i+1<argc)rpcport=std::stoi(argv[++i]);
    else if(a[0]!='-'){ method=a; if(i+1<argc&&argv[i+1][0]=='{') params=argv[++i]; } }
  if(argc<2){ std::cout<<"coin-cli [--rpcport P] getblockchaininfo|getblocktemplate|submitblock {..}|sendrawtransaction {..}\n"; return 0; }
  std::cout<<rpcCall(rpcport,method,params)<<"\n"; return 0;
}
