#include "crypto/Hmac.h"

#include <openssl/mem.h>
#include <openssl/sha.h>

#include <cstring>

namespace pp {

static_assert(sizeof(SHA256_CTX) <= HmacSha256::kStateBytes);
static_assert(alignof(SHA256_CTX) <= 16);

namespace {

constexpr size_t kBlockBytes = 64;

void HashPad(const uint8_t* key, size_t key_len, uint8_t pad_byte, unsigned char* state) {
  uint8_t block[kBlockBytes];
  std::memset(block, pad_byte, sizeof(block));
  for (size_t i = 0; i < key_len; ++i) {
    block[i] ^= key[i];
  }
  SHA256_CTX ctx;
  SHA256_Init(&ctx);
  SHA256_Update(&ctx, block, sizeof(block));
  std::memcpy(state, &ctx, sizeof(ctx));
  OPENSSL_cleanse(block, sizeof(block));
  OPENSSL_cleanse(&ctx, sizeof(ctx));
}

} // namespace

HmacSha256::HmacSha256(std::span<const uint8_t> key) {
  // RFC 2104: a key longer than a block is hashed first.
  uint8_t hashed[SHA256_DIGEST_LENGTH];
  const uint8_t* k = key.data();
  size_t k_len = key.size();
  if (k_len > kBlockBytes) {
    SHA256(key.data(), key.size(), hashed);
    k = hashed;
    k_len = sizeof(hashed);
  }
  HashPad(k, k_len, 0x36, inner_);
  HashPad(k, k_len, 0x5c, outer_);
  OPENSSL_cleanse(hashed, sizeof(hashed));
}

HmacSha256::~HmacSha256() {
  OPENSSL_cleanse(inner_, sizeof(inner_));
  OPENSSL_cleanse(outer_, sizeof(outer_));
}

HmacSha256::Tag HmacSha256::Mac(std::span<const uint8_t> data) const {
  SHA256_CTX ctx;
  std::memcpy(&ctx, inner_, sizeof(ctx));
  SHA256_Update(&ctx, data.data(), data.size());
  uint8_t inner_hash[SHA256_DIGEST_LENGTH];
  SHA256_Final(inner_hash, &ctx);
  std::memcpy(&ctx, outer_, sizeof(ctx));
  SHA256_Update(&ctx, inner_hash, sizeof(inner_hash));
  Tag tag;
  SHA256_Final(tag.data(), &ctx);
  OPENSSL_cleanse(&ctx, sizeof(ctx));
  return tag;
}

HmacSha256::Tag HmacSha256::Compute(std::span<const uint8_t> key, std::span<const uint8_t> data) {
  return HmacSha256(key).Mac(data);
}

} // namespace pp
