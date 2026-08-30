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
/** FIPS 203 ML-KEM.KeyGen_Internal coins length (2 × SYMBYTES). */
inline constexpr size_t kMlKem768KeygenCoinsBytes = 64;

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
  /** Deterministic KeyGen_Internal from 64-byte coins. */
  static Roe<MlKemKeyPair> GenerateKeyPairFromSeed(const ByteVector& coins);
  static Roe<MlKemEncapResult> Encapsulate(const ByteVector& peer_public_key);
  static Roe<ByteVector> Decapsulate(const ByteVector& private_key, const ByteVector& ciphertext);
};

} // namespace pp
