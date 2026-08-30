#include "crypto/MlKem.h"

#include "crypto/SodiumUtil.h"

#include <mlkem_native.h>

namespace pp {

Roe<MlKemKeyPair> MlKem::GenerateKeyPair() {
  EnsureSodiumInit();
  MlKemKeyPair keys;
  keys.public_key.resize(kMlKem768PublicKeyBytes);
  keys.private_key.resize(kMlKem768PrivateKeyBytes);
  if (mlkem_keypair(keys.public_key.data(), keys.private_key.data()) != 0) {
    return Error("ML-KEM-768 keygen failed");
  }
  return keys;
}

Roe<MlKemKeyPair> MlKem::GenerateKeyPairFromSeed(const ByteVector& coins) {
  if (coins.size() != kMlKem768KeygenCoinsBytes) {
    return Error("ML-KEM-768 keygen coins must be 64 bytes");
  }
  EnsureSodiumInit();
  MlKemKeyPair keys;
  keys.public_key.resize(kMlKem768PublicKeyBytes);
  keys.private_key.resize(kMlKem768PrivateKeyBytes);
  if (mlkem_keypair_derand(keys.public_key.data(), keys.private_key.data(), coins.data()) != 0) {
    return Error("ML-KEM-768 seeded keygen failed");
  }
  return keys;
}

Roe<MlKemEncapResult> MlKem::Encapsulate(const ByteVector& peer_public_key) {
  if (peer_public_key.size() != kMlKem768PublicKeyBytes) {
    return Error("Invalid ML-KEM-768 public key size");
  }
  EnsureSodiumInit();

  MlKemEncapResult result;
  result.ciphertext.resize(kMlKem768CiphertextBytes);
  result.shared_secret.resize(kMlKem768SharedSecretBytes);
  if (mlkem_enc(result.ciphertext.data(), result.shared_secret.data(), peer_public_key.data()) != 0) {
    return Error("ML-KEM-768 encapsulation failed");
  }
  return result;
}

Roe<ByteVector> MlKem::Decapsulate(const ByteVector& private_key, const ByteVector& ciphertext) {
  if (private_key.size() != kMlKem768PrivateKeyBytes) {
    return Error("Invalid ML-KEM-768 private key size");
  }
  if (ciphertext.size() != kMlKem768CiphertextBytes) {
    return Error("Invalid ML-KEM-768 ciphertext size");
  }
  EnsureSodiumInit();

  ByteVector shared_secret(kMlKem768SharedSecretBytes);
  if (mlkem_dec(shared_secret.data(), ciphertext.data(), private_key.data()) != 0) {
    return Error("ML-KEM-768 decapsulation failed");
  }
  return shared_secret;
}

} // namespace pp
