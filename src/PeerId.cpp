#include "crypto/PeerId.h"

#include "crypto/MlDsa.h"
#include "crypto/SodiumUtil.h"

#include <sodium.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace pp {
namespace {

constexpr char kBase58Alphabet[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
/** Our KeyType for ML-DSA-65 in libp2p's `PublicKey` protobuf. */
constexpr uint64_t kKeyTypeMlDsa65 = 4;
/** Multihash code of sha2-256. */
constexpr uint8_t kMultihashSha256 = 0x12;

void AppendVarint(std::vector<uint8_t>& out, uint64_t value) {
  while (value >= 0x80) {
    out.push_back(static_cast<uint8_t>((value & 0x7f) | 0x80));
    value >>= 7;
  }
  out.push_back(static_cast<uint8_t>(value));
}

/** libp2p `PublicKey { KeyType Type = 1; bytes Data = 2; }`, deterministic. */
std::vector<uint8_t> PublicKeyEncoding(const ByteVector& key) {
  std::vector<uint8_t> out;
  out.reserve(key.size() + 8);
  AppendVarint(out, (1u << 3) | 0u);  // field 1, varint
  AppendVarint(out, kKeyTypeMlDsa65);
  AppendVarint(out, (2u << 3) | 2u);  // field 2, length-delimited
  AppendVarint(out, key.size());
  out.insert(out.end(), key.begin(), key.end());
  return out;
}

std::string EncodeBase58(const std::vector<uint8_t>& bytes) {
  size_t zeros = 0;
  while (zeros < bytes.size() && bytes[zeros] == 0) {
    ++zeros;
  }
  // log(256) / log(58) ≈ 1.37: enough base-58 digits for the input.
  std::vector<uint8_t> digits((bytes.size() - zeros) * 138 / 100 + 1, 0);
  size_t length = 0;
  for (size_t i = zeros; i < bytes.size(); ++i) {
    int carry = bytes[i];
    size_t j = 0;
    for (auto it = digits.rbegin(); (carry != 0 || j < length) && it != digits.rend(); ++it, ++j) {
      carry += 256 * *it;
      *it = static_cast<uint8_t>(carry % 58);
      carry /= 58;
    }
    length = j;
  }
  auto it = digits.begin() + static_cast<std::ptrdiff_t>(digits.size() - length);
  while (it != digits.end() && *it == 0) {
    ++it;
  }
  std::string out(zeros, '1');
  for (; it != digits.end(); ++it) {
    out.push_back(kBase58Alphabet[*it]);
  }
  return out;
}

} // namespace

Roe<std::string> PeerIdFromMlDsaPublicKey(const ByteVector& public_key) {
  if (public_key.size() != kMlDsa65PublicKeyBytes) {
    return Error("ML-DSA-65 public key must be 1952 bytes");
  }
  EnsureSodiumInit();
  const std::vector<uint8_t> encoding = PublicKeyEncoding(public_key);
  std::array<uint8_t, crypto_hash_sha256_BYTES> digest{};
  crypto_hash_sha256(digest.data(), encoding.data(), encoding.size());
  std::vector<uint8_t> multihash{kMultihashSha256, static_cast<uint8_t>(digest.size())};
  multihash.insert(multihash.end(), digest.begin(), digest.end());
  return EncodeBase58(multihash);
}

} // namespace pp
