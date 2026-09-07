#pragma once
#include <cstdint>
#include <vector>
#include <string>
#include <cstring>
#include <stdexcept>
struct SerWriter {
  std::vector<uint8_t> v;
  void u8(uint8_t x){v.push_back(x);} void u16(uint16_t x){v.push_back(x);v.push_back(x>>8);}
  void u32(uint32_t x){for(int i=0;i<4;++i)v.push_back(x>>(8*i));}
  void u64(uint64_t x){for(int i=0;i<8;++i)v.push_back(x>>(8*i));}
  void i64(int64_t x){u64((uint64_t)x);}
  void bytes(const uint8_t* d,size_t n){v.insert(v.end(),d,d+n);}
  void bytes(const std::vector<uint8_t>& b){bytes(b.data(),b.size());}
  void varint(uint64_t x){ if(x<0xfd)u8(x); else if(x<=0xffff){u8(0xfd);u16(x);} else if(x<=0xffffffff){u8(0xfe);u32(x);} else {u8(0xff);u64(x);} }
  void str(const std::string& s){varint(s.size());bytes((const uint8_t*)s.data(),s.size());}
};
struct SerReader {
  const uint8_t* p; size_t n, off=0;
  SerReader(const std::vector<uint8_t>& v):p(v.data()),n(v.size()){}
  SerReader(const uint8_t*d,size_t n):p(d),n(n){}
  void need(size_t k){ if(off+k>n||off+k<off) throw std::runtime_error("deserialize: truncated"); }
  // Length is validated BEFORE any allocation, so a corrupt length prefix
  // can never cause OOM: it fails fast here instead.
  void needBounded(size_t k,size_t maxLen,const char* what){
    if(k>maxLen) throw std::runtime_error(std::string("deserialize: ")+what);
    need(k);
  }
  uint8_t u8(){need(1);return p[off++];} uint16_t u16(){need(2);uint16_t x=p[off]|(p[off+1]<<8);off+=2;return x;}
  uint32_t u32(){need(4);uint32_t x=0;for(int i=0;i<4;++i)x|=((uint32_t)p[off+i]<<(8*i));off+=4;return x;}
  uint64_t u64(){need(8);uint64_t x=0;for(int i=0;i<8;++i)x|=((uint64_t)p[off+i]<<(8*i));off+=8;return x;}
  int64_t i64(){return (int64_t)u64();}
  std::vector<uint8_t> bytes(size_t k){need(k);std::vector<uint8_t> o(p+off,p+off+k);off+=k;return o;}
  std::vector<uint8_t> bytesBounded(size_t k,size_t maxLen){needBounded(k,maxLen,"oversize blob");return bytes(k);}
  uint64_t varint(){uint8_t f=u8(); if(f<0xfd)return f; if(f==0xfd)return u16(); if(f==0xfe)return u32(); return u64();}
  uint64_t varintBounded(uint64_t maxVal){uint64_t v=varint(); if(v>maxVal) throw std::runtime_error("deserialize: oversize count"); return v;}
  std::string str(){auto k=(size_t)varint();auto b=bytes(k);return {(char*)b.data(),k};}
  std::string strBounded(size_t maxLen){auto k=(size_t)varintBounded(maxLen);auto b=bytes(k);return {(char*)b.data(),k};}
  bool eof()const{return off>=n;}
};
// DoS caps: generous vs any legitimate data, tiny vs memory.
static constexpr size_t MAX_TX_INPUTS = 100000;
static constexpr size_t MAX_TX_OUTPUTS = 100000;
static constexpr size_t MAX_SCRIPT_SIZE = 1024*1024;   // consensus needs <= 100
static constexpr size_t MAX_TXS_PER_BLOCK = 100000;    // consensus needs <= 10000
static constexpr size_t MAX_TX_BYTES = 4*1024*1024;    // consensus block cap is 2MB
static constexpr size_t MAX_BLOCK_BYTES = 2*1024*1024 + 1024; // wire/storage cap
static constexpr size_t MAX_WALLET_KEYS = 10000;
static constexpr size_t MAX_ADDR_LEN = 128;
static constexpr size_t MAX_WALLET_FILE = 32*1024*1024;
static constexpr size_t MAX_RPC_HEX = 5*1024*1024;      // ~2MB block as hex + slack
