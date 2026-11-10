#pragma once

#include "crypto/Types.h"

#include "common/Error.h"

#include <cstddef>
#include <cstdint>
#include <span>

namespace pp {

/**
 * XChaCha20-Poly1305 (IETF) authenticated encryption with associated data. A 32-byte key, a 24-byte
 * nonce — random nonces are safe at this size — and a 16-byte tag appended to the ciphertext.
 *
 * Sealed by BoringSSL, whose fused ChaCha20-Poly1305 assembly is the fastest we build; the bytes are
 * libsodium's `crypto_aead_xchacha20poly1305_ietf_*` exactly, so either end may use either library.
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

  /**
   * Encrypt `plaintext` into `out`, which needs `plaintext.size() + kTagBytes` bytes; returns the
   * bytes written. `out` may be `plaintext` itself, but must not partly overlap it. No allocation:
   * the per-packet path.
   */
  static Roe<size_t> SealInto(std::span<const uint8_t> key, std::span<const uint8_t> nonce,
                              std::span<const uint8_t> plaintext, std::span<const uint8_t> aad, std::span<uint8_t> out);
  /**
   * Check the tag and decrypt `ciphertext` (with the tag) into `out`, which needs
   * `ciphertext.size() - kTagBytes` bytes; returns the bytes written. Same aliasing rule.
   */
  static Roe<size_t> OpenInto(std::span<const uint8_t> key, std::span<const uint8_t> nonce,
                              std::span<const uint8_t> ciphertext, std::span<const uint8_t> aad,
                              std::span<uint8_t> out);

  /** Encrypt `plaintext` under `key` and `nonce`, authenticating `aad` too. */
  static Roe<Sealed> Seal(const ByteVector& key, const ByteVector& plaintext, const ByteVector& aad,
                          const ByteVector& nonce);
  /** Decrypt and check the tag (and `aad`); an error when anything was altered. */
  static Roe<ByteVector> Open(const ByteVector& key, const Sealed& sealed, const ByteVector& aad);
};

} // namespace pp
