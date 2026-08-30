#include "crypto/MlDsa.h"

#include "crypto/SodiumUtil.h"

#include <mldsa_native.h>

namespace pp {

Roe<MlDsaKeyPair> MlDsa::GenerateKeyPair() {
  EnsureSodiumInit();
  MlDsaKeyPair keys;
  keys.public_key.resize(kMlDsa65PublicKeyBytes);
  keys.secret_key.resize(kMlDsa65SecretKeyBytes);
  if (mldsa_keypair(keys.public_key.data(), keys.secret_key.data()) != 0) {
    return Error("ML-DSA-65 keygen failed");
  }
  return keys;
}

Roe<MlDsaKeyPair> MlDsa::GenerateKeyPairFromSeed(const ByteVector& seed) {
  if (seed.size() != kMlDsa65SeedBytes) {
    return Error("ML-DSA-65 seed must be 32 bytes");
  }
  EnsureSodiumInit();
  MlDsaKeyPair keys;
  keys.public_key.resize(kMlDsa65PublicKeyBytes);
  keys.secret_key.resize(kMlDsa65SecretKeyBytes);
  if (mldsa_keypair_internal(keys.public_key.data(), keys.secret_key.data(), seed.data()) != 0) {
    return Error("ML-DSA-65 seeded keygen failed");
  }
  return keys;
}

Roe<ByteVector> MlDsa::Sign(const ByteVector& secret_key, const ByteVector& message) {
  if (secret_key.size() != kMlDsa65SecretKeyBytes) {
    return Error("Invalid ML-DSA-65 secret key size");
  }
  EnsureSodiumInit();
  ByteVector sig(kMlDsa65SignatureBytes);
  if (mldsa_signature(sig.data(), message.data(), message.size(), nullptr, 0, secret_key.data()) != 0) {
    return Error("ML-DSA-65 sign failed");
  }
  return sig;
}

Roe<bool> MlDsa::Verify(const ByteVector& public_key, const ByteVector& message,
                        const ByteVector& signature) {
  if (public_key.size() != kMlDsa65PublicKeyBytes) {
    return Error("Invalid ML-DSA-65 public key size");
  }
  if (signature.size() != kMlDsa65SignatureBytes) {
    return Error("Invalid ML-DSA-65 signature size");
  }
  EnsureSodiumInit();
  const int rc = mldsa_verify(signature.data(), message.data(), message.size(), nullptr, 0, public_key.data());
  if (rc == 0) {
    return true;
  }
  return false;
}

} // namespace pp
