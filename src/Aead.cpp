#include "crypto/Aead.h"

#include "crypto/SodiumUtil.h"

#include <openssl/aead.h>
#include <openssl/mem.h>
#include <sodium.h>

namespace pp {

static_assert(XChaCha20Poly1305::kKeyBytes == crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
static_assert(XChaCha20Poly1305::kNonceBytes == crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
static_assert(XChaCha20Poly1305::kTagBytes == crypto_aead_xchacha20poly1305_ietf_ABYTES);

namespace {

// One BoringSSL context per call: for ChaCha20 the key setup is a copy, and the key leaves the stack
// wiped when the call ends.
class AeadContext {
public:
  explicit AeadContext(std::span<const uint8_t> key) {
    EVP_AEAD_CTX_zero(&ctx_);
    ok_ = EVP_AEAD_CTX_init(&ctx_, EVP_aead_xchacha20_poly1305(), key.data(), key.size(), XChaCha20Poly1305::kTagBytes,
                            nullptr) == 1;
  }
  ~AeadContext() {
    EVP_AEAD_CTX_cleanup(&ctx_);
    OPENSSL_cleanse(&ctx_, sizeof(ctx_));
  }
  AeadContext(const AeadContext&) = delete;
  AeadContext& operator=(const AeadContext&) = delete;

  bool ok() const { return ok_; }
  EVP_AEAD_CTX* get() { return &ctx_; }

private:
  EVP_AEAD_CTX ctx_;
  bool ok_ = false;
};

/** What is wrong with the sizes, or null. */
const char* SizeError(std::span<const uint8_t> key, std::span<const uint8_t> nonce) {
  if (key.size() != XChaCha20Poly1305::kKeyBytes) {
    return "Invalid session key size";
  }
  if (nonce.size() != XChaCha20Poly1305::kNonceBytes) {
    return "Invalid nonce size";
  }
  return nullptr;
}

} // namespace

ByteVector XChaCha20Poly1305::RandomNonce() {
  EnsureSodiumInit();
  ByteVector nonce(kNonceBytes);
  randombytes_buf(nonce.data(), nonce.size());
  return nonce;
}

Roe<size_t> XChaCha20Poly1305::SealInto(std::span<const uint8_t> key, std::span<const uint8_t> nonce,
                                        std::span<const uint8_t> plaintext, std::span<const uint8_t> aad,
                                        std::span<uint8_t> out) {
  if (const char* bad = SizeError(key, nonce)) {
    return Error(bad);
  }
  if (out.size() < plaintext.size() + kTagBytes) {
    return Error("AEAD ciphertext buffer too small");
  }
  AeadContext ctx(key);
  size_t length = 0;
  if (!ctx.ok() || EVP_AEAD_CTX_seal(ctx.get(), out.data(), &length, out.size(), nonce.data(), nonce.size(),
                                     plaintext.data(), plaintext.size(), aad.data(), aad.size()) != 1) {
    return Error("AEAD encrypt failed");
  }
  return length;
}

Roe<size_t> XChaCha20Poly1305::OpenInto(std::span<const uint8_t> key, std::span<const uint8_t> nonce,
                                        std::span<const uint8_t> ciphertext, std::span<const uint8_t> aad,
                                        std::span<uint8_t> out) {
  if (const char* bad = SizeError(key, nonce)) {
    return Error(bad);
  }
  if (ciphertext.size() < kTagBytes) {
    return Error("AEAD decrypt failed");
  }
  if (out.size() < ciphertext.size() - kTagBytes) {
    return Error("AEAD plaintext buffer too small");
  }
  AeadContext ctx(key);
  size_t length = 0;
  if (!ctx.ok() || EVP_AEAD_CTX_open(ctx.get(), out.data(), &length, out.size(), nonce.data(), nonce.size(),
                                     ciphertext.data(), ciphertext.size(), aad.data(), aad.size()) != 1) {
    return Error("AEAD decrypt failed");
  }
  return length;
}

Roe<XChaCha20Poly1305::Sealed> XChaCha20Poly1305::Seal(const ByteVector& key, const ByteVector& plaintext,
                                                       const ByteVector& aad, const ByteVector& nonce) {
  Sealed sealed;
  sealed.nonce = nonce;
  sealed.ciphertext.resize(plaintext.size() + kTagBytes);
  auto length = SealInto(key, nonce, plaintext, aad, sealed.ciphertext);
  if (!length) {
    return length.error();
  }
  sealed.ciphertext.resize(*length);
  return sealed;
}

Roe<ByteVector> XChaCha20Poly1305::Open(const ByteVector& key, const Sealed& sealed, const ByteVector& aad) {
  ByteVector plaintext(sealed.ciphertext.size() >= kTagBytes ? sealed.ciphertext.size() - kTagBytes : 0);
  auto length = OpenInto(key, sealed.nonce, sealed.ciphertext, aad, plaintext);
  if (!length) {
    return length.error();
  }
  plaintext.resize(*length);
  return plaintext;
}

} // namespace pp
