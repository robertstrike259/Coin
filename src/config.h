#pragma once
#include <string>
#include "chainparams.h"
struct Config {
  std::string datadir="~/.coin", net="regtest";
  int port=0, rpcport=0; std::string miningAddress; int threads=1;
  ChainParams params(){ if(net=="main")return mainParams(); if(net=="testnet")return testParams(); return regtestParams(); }
};
Config parseArgs(int argc,char**argv,const char* app);
std::string expandHome(const std::string& s);
