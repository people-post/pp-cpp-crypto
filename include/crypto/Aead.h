#pragma once

#include "crypto/Types.h"

#include "common/Error.h"

#include <cstddef>

namespace pp {

/**
 * XChaCha20-Poly1305 (IETF) authenticated encryption with associated data, over libsodium. A 32-byte
 * key, a 24-byte nonce — random nonces are safe at this size — and a 16-byte tag appended to the
 * ciphertext.
 */
class XChaCha20Poly1305 {
public:
  static constexpr size_t kKeyBytes = 32;
  static constexpr size_t kNonceBytes = 24;
  static constexpr size_t kTagBytes = 16;

  struct Sealed {
    ByteVector nonce;
    /** The ciphertext with the tag appended. */
    ByteVector ciphertext;
  };

  /** A fresh random nonce. */
  static ByteVector RandomNonce();
  /** Encrypt `plaintext` under `key` and `nonce`, authenticating `aad` too. */
  static Roe<Sealed> Seal(const ByteVector& key, const ByteVector& plaintext, const ByteVector& aad,
                          const ByteVector& nonce);
  /** Decrypt and check the tag (and `aad`); an error when anything was altered. */
  static Roe<ByteVector> Open(const ByteVector& key, const Sealed& sealed, const ByteVector& aad);
};

} // namespace pp
