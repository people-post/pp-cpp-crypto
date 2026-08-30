#pragma once

#include "crypto/Types.h"

#include "common/Error.h"

#include <cstddef>

namespace pp {

/** ML-DSA-65 (FIPS 204) via vendored mldsa-native. */
inline constexpr size_t kMlDsa65PublicKeyBytes = 1952;
inline constexpr size_t kMlDsa65SecretKeyBytes = 4032;
inline constexpr size_t kMlDsa65SignatureBytes = 3309;
/** FIPS 204 ML-DSA.KeyGen_internal seed length. */
inline constexpr size_t kMlDsa65SeedBytes = 32;

struct MlDsaKeyPair {
  ByteVector public_key;
  ByteVector secret_key;
};

class MlDsa {
public:
  static Roe<MlDsaKeyPair> GenerateKeyPair();
  /** Deterministic KeyGen_internal from a 32-byte seed. */
  static Roe<MlDsaKeyPair> GenerateKeyPairFromSeed(const ByteVector& seed);
  /** Randomized ML-DSA.Sign; empty ctx allowed. */
  static Roe<ByteVector> Sign(const ByteVector& secret_key, const ByteVector& message);
  static Roe<bool> Verify(const ByteVector& public_key, const ByteVector& message,
                          const ByteVector& signature);
};

} // namespace pp
