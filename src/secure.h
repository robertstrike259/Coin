#pragma once
// Secure in-memory secrets (passphrases). std::string is unsuitable: SSO
// leaves copies in moved-from objects and frees buffers without cleansing.
// SecureString uses a heap-only vector (single allocation, reserved upfront
// so prompt/file reads never reallocate), cleanses on clear() and destroy,
// and is move-only so copies cannot proliferate by accident.
#include <cstddef>
#include <cstdint>
#include <vector>
#include <openssl/crypto.h>

class SecureString {
  std::vector<char> buf_; // heap only; buf_[i] valid for i < size_
 public:
  SecureString() { buf_.reserve(1024); }
  SecureString(const SecureString&) = delete;
  SecureString& operator=(const SecureString&) = delete;
  SecureString(SecureString&& o) noexcept : buf_(std::move(o.buf_)) {}
  SecureString& operator=(SecureString&& o) noexcept {
    if (this != &o) {
      clear();
      buf_ = std::move(o.buf_);
    }
    return *this;
  }
  ~SecureString() { clear(); }
  // Append callers must stay within the upfront reservation; returns false
  // instead of reallocating (which would orphan a dirty heap buffer).
  bool push_back(char c) {
    if (buf_.size() >= buf_.capacity()) return false;
    buf_.push_back(c);
    return true;
  }
  void assign(const char* s, size_t n) {
    clear();
    if (n > buf_.capacity()) n = buf_.capacity();
    buf_.assign(s, s + n);
  }
  const char* data() const { return buf_.data(); }
  size_t size() const { return buf_.size(); }
  bool empty() const { return buf_.empty(); }
  void clear() {
    if (!buf_.empty()) OPENSSL_cleanse(buf_.data(), buf_.size());
    buf_.clear(); // keeps capacity: no free/realloc of dirty memory
  }
};
