#pragma once

#include "crypto/Types.h"

#include "common/Error.h"

#include <cstddef>

namespace pp {

/** ML-DSA-65 (FIPS 204) via vendored mldsa-native. */
inline constexpr size_t kMlDsa65PublicKeyBytes = 1952;
inline constexpr size_t kMlDsa65SecretKeyBytes = 4032;
inline constexpr size_t kMlDsa65SignatureBytes = 3309;

struct MlDsaKeyPair {
  ByteVector public_key;
  ByteVector secret_key;
};

class MlDsa {
public:
  static Roe<MlDsaKeyPair> GenerateKeyPair();
  /** Randomized ML-DSA.Sign; empty ctx allowed. */
  static Roe<ByteVector> Sign(const ByteVector& secret_key, const ByteVector& message);
  static Roe<bool> Verify(const ByteVector& public_key, const ByteVector& message,
                          const ByteVector& signature);
};

} // namespace pp
