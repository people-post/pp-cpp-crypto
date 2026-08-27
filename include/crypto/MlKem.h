#pragma once

#include "crypto/Types.h"

#include "common/Error.h"

#include <cstddef>

namespace pp {

/** ML-KEM-768 (FIPS 203) via vendored mlkem-native. */
inline constexpr size_t kMlKem768PublicKeyBytes = 1184;
inline constexpr size_t kMlKem768CiphertextBytes = 1088;
inline constexpr size_t kMlKem768SharedSecretBytes = 32;
inline constexpr size_t kMlKem768PrivateKeyBytes = 2400;

struct MlKemKeyPair {
  ByteVector public_key;
  ByteVector private_key;
};

struct MlKemEncapResult {
  ByteVector shared_secret;
  ByteVector ciphertext;
};

class MlKem {
public:
  static Roe<MlKemKeyPair> GenerateKeyPair();
  static Roe<MlKemEncapResult> Encapsulate(const ByteVector& peer_public_key);
  static Roe<ByteVector> Decapsulate(const ByteVector& private_key, const ByteVector& ciphertext);
};

} // namespace pp
