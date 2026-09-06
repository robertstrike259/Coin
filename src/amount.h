#pragma once
#include <cstdint>
#include <cstdio>
#include <string>
// Amounts in swarf. 1 CON = 100,000,000 swarf.
using CAmount = int64_t;
static constexpr CAmount SWARF_PER_COIN = 100000000LL;
static constexpr CAmount MAX_MONEY_SWARF = 84000000LL * SWARF_PER_COIN; // + tail
inline bool moneyRange(CAmount a){ return a>=0 && a<= 200000000LL*SWARF_PER_COIN; }
inline std::string fmtCon(CAmount s){ char b[64]; bool neg=s<0; if(neg)s=-s;
  snprintf(b,sizeof b,"%s%lld.%08lld",neg?"-":"",(long long)(s/SWARF_PER_COIN),(long long)(s%SWARF_PER_COIN)); return b; }
