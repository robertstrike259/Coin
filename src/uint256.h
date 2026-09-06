#pragma once
#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
// 256-bit LE integer for hashes/targets.
struct uint256 {
  std::array<uint8_t,32> d{};
  uint256(){d.fill(0);}
  explicit uint256(const std::vector<uint8_t>& v){d.fill(0);memcpy(d.data(),v.data(),std::min<size_t>(32,v.size()));}
  bool operator==(const uint256& o) const { return d==o.d; }
  bool operator!=(const uint256& o) const { return d!=o.d; }
  bool operator<(const uint256& o) const {
    for(int i=31;i>=0;--i){ if(d[i]<o.d[i])return true; if(d[i]>o.d[i])return false; } return false;
  }
  bool operator<=(const uint256& o) const { return *this<o||*this==o; }
  bool isZero() const { for(auto b:d) if(b) return false; return true; }
  std::string hex() const {
    static const char* h="0123456789abcdef"; std::string s; s.reserve(64);
    for(int i=31;i>=0;--i){ s.push_back(h[d[i]>>4]); s.push_back(h[d[i]&15]); } return s;
  }
  static uint256 fromHex(const std::string& s){
    uint256 u; auto hv=[](char c)->int{ if(c>='0'&&c<='9')return c-'0'; if(c>='a'&&c<='f')return c-'a'+10; if(c>='A'&&c<='F')return c-'A'+10; return 0; };
    for(int i=0;i<32 && (size_t)(i*2+1)<s.size();++i){ int hi=hv(s[s.size()-1-i*2-1]), lo=hv(s[s.size()-1-i*2]); u.d[i]=(hi<<4)|lo; }
    return u;
  }
  std::vector<uint8_t> bytes() const { return {d.begin(),d.end()}; }
};
