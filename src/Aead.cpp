#include "crypto/Aead.h"

#include "crypto/SodiumUtil.h"

#include <sodium.h>

namespace pp {

static_assert(XChaCha20Poly1305::kKeyBytes == crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
static_assert(XChaCha20Poly1305::kNonceBytes == crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
static_assert(XChaCha20Poly1305::kTagBytes == crypto_aead_xchacha20poly1305_ietf_ABYTES);

ByteVector XChaCha20Poly1305::RandomNonce() {
  EnsureSodiumInit();
  ByteVector nonce(kNonceBytes);
  randombytes_buf(nonce.data(), nonce.size());
  return nonce;
}

Roe<XChaCha20Poly1305::Sealed> XChaCha20Poly1305::Seal(const ByteVector& key, const ByteVector& plaintext,
                                                       const ByteVector& aad, const ByteVector& nonce) {
  if (key.size() != kKeyBytes) {
    return Error("Invalid session key size");
  }
  if (nonce.size() != kNonceBytes) {
    return Error("Invalid nonce size");
  }
  EnsureSodiumInit();
  Sealed sealed;
  sealed.nonce = nonce;
  sealed.ciphertext.resize(plaintext.size() + kTagBytes);
  unsigned long long length = 0;
  if (crypto_aead_xchacha20poly1305_ietf_encrypt(sealed.ciphertext.data(), &length, plaintext.data(), plaintext.size(),
                                                 aad.data(), aad.size(), nullptr, nonce.data(), key.data()) != 0) {
    return Error("AEAD encrypt failed");
  }
  sealed.ciphertext.resize(static_cast<size_t>(length));
  return sealed;
}

Roe<ByteVector> XChaCha20Poly1305::Open(const ByteVector& key, const Sealed& sealed, const ByteVector& aad) {
  if (key.size() != kKeyBytes) {
    return Error("Invalid session key size");
  }
  if (sealed.nonce.size() != kNonceBytes) {
    return Error("Invalid nonce size");
  }
  EnsureSodiumInit();
  ByteVector plaintext(sealed.ciphertext.size());
  unsigned long long length = 0;
  if (crypto_aead_xchacha20poly1305_ietf_decrypt(plaintext.data(), &length, nullptr, sealed.ciphertext.data(),
                                                 sealed.ciphertext.size(), aad.data(), aad.size(), sealed.nonce.data(),
                                                 key.data()) != 0) {
    return Error("AEAD decrypt failed");
  }
  plaintext.resize(static_cast<size_t>(length));
  return plaintext;
}

} // namespace pp
