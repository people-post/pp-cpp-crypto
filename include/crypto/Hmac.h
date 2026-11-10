#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace pp {

/**
 * HMAC-SHA256 under one key. The key's pads are hashed once, at construction, so each Mac() costs two
 * SHA-256 blocks fewer than a fresh HMAC — most of the cost for a small packet. Over BoringSSL, whose
 * SHA-256 uses the CPU's SHA extensions where it has them; the bytes are libsodium's
 * `crypto_auth_hmacsha256` (and RFC 2104's) for a key of any length.
 *
 * Mac() is const and safe to call from several threads at once. The keyed state is wiped on destruction.
 */
class HmacSha256 {
public:
  static constexpr size_t kBytes = 32;
  using Tag = std::array<uint8_t, kBytes>;

  explicit HmacSha256(std::span<const uint8_t> key);
  ~HmacSha256();
  HmacSha256(const HmacSha256&) = default;
  HmacSha256& operator=(const HmacSha256&) = default;

  Tag Mac(std::span<const uint8_t> data) const;

  /** One message under a key used once. */
  static Tag Compute(std::span<const uint8_t> key, std::span<const uint8_t> data);

  /** Room for a SHA-256 midstate (BoringSSL's SHA256_CTX; checked where it is defined). */
  static constexpr size_t kStateBytes = 128;

private:
  alignas(16) unsigned char inner_[kStateBytes];
  alignas(16) unsigned char outer_[kStateBytes];
};

} // namespace pp
