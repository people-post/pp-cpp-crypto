#include "crypto/SodiumUtil.h"

#include <cstring>

#include <sodium.h>

#include <cctype>

namespace pp {

namespace {

bool IsHexDigit(const char c) {
  return std::isxdigit(static_cast<unsigned char>(c)) != 0;
}

} // namespace

void EnsureSodiumInit() {
  static const bool initialized = [] {
    if (sodium_init() < 0) {
      return false;
    }
    return true;
  }();
  (void)initialized;
}

Roe<ByteVector> HexToBytes(const std::string_view hex) {
  if (hex.size() % 2 != 0) {
    return Error("Invalid hex length");
  }
  ByteVector out;
  out.reserve(hex.size() / 2);
  for (size_t i = 0; i < hex.size(); i += 2) {
    if (!IsHexDigit(hex[i]) || !IsHexDigit(hex[i + 1])) {
      return Error("Invalid hex character");
    }
    const auto nibble = [](const char c) -> uint8_t {
      if (c >= '0' && c <= '9') {
        return static_cast<uint8_t>(c - '0');
      }
      if (c >= 'a' && c <= 'f') {
        return static_cast<uint8_t>(10 + c - 'a');
      }
      return static_cast<uint8_t>(10 + c - 'A');
    };
    out.push_back(static_cast<uint8_t>((nibble(hex[i]) << 4) | nibble(hex[i + 1])));
  }
  return out;
}

std::string BytesToHex(const ByteVector& bytes) {
  static constexpr char kHex[] = "0123456789abcdef";
  std::string out;
  out.reserve(bytes.size() * 2);
  for (const uint8_t byte : bytes) {
    out.push_back(kHex[byte >> 4]);
    out.push_back(kHex[byte & 0x0f]);
  }
  return out;
}

Roe<ByteVector> Base64Decode(const std::string& encoded) {
  EnsureSodiumInit();
  ByteVector out(encoded.size());
  size_t out_len = 0;
  if (sodium_base642bin(out.data(), out.size(), encoded.c_str(), encoded.size(), nullptr, &out_len, nullptr,
                        sodium_base64_VARIANT_ORIGINAL) != 0) {
    return Error("Base64 decode failed");
  }
  out.resize(out_len);
  return out;
}

std::string Base64Encode(const ByteVector& bytes) {
  EnsureSodiumInit();
  const size_t max_len = sodium_base64_ENCODED_LEN(bytes.size(), sodium_base64_VARIANT_ORIGINAL);
  std::string out(max_len, '\0');
  sodium_bin2base64(out.data(), out.size(), bytes.data(), bytes.size(), sodium_base64_VARIANT_ORIGINAL);
  while (!out.empty() && out.back() == '\0') {
    out.pop_back();
  }
  return out;
}

std::string Base64UrlEncode(const ByteVector& bytes) {
  EnsureSodiumInit();
  std::string out(sodium_base64_ENCODED_LEN(bytes.size(), sodium_base64_VARIANT_URLSAFE_NO_PADDING), '\0');
  sodium_bin2base64(out.data(), out.size(), bytes.data(), bytes.size(), sodium_base64_VARIANT_URLSAFE_NO_PADDING);
  out.resize(std::strlen(out.c_str()));
  return out;
}

Roe<ByteVector> Base64UrlDecode(const std::string& encoded) {
  EnsureSodiumInit();
  ByteVector out(encoded.size());
  size_t length = 0;
  if (sodium_base642bin(out.data(), out.size(), encoded.data(), encoded.size(), nullptr, &length, nullptr,
                        sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0) {
    return Error("Invalid base64url");
  }
  out.resize(length);
  return out;
}

ByteVector Blake2b256(const ByteVector& data) {
  EnsureSodiumInit();
  ByteVector hash(crypto_generichash_BYTES);
  crypto_generichash(hash.data(), hash.size(), data.data(), data.size(), nullptr, 0);
  return hash;
}

} // namespace pp
