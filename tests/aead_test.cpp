#include "crypto/Aead.h"
#include "crypto/SodiumUtil.h"

#include <gtest/gtest.h>

namespace pp {
namespace {

const ByteVector kKey(XChaCha20Poly1305::kKeyBytes, 0x11);

TEST(XChaCha20Poly1305Test, RoundTripsAndAuthenticatesTheAad) {
  const ByteVector plain = {'h', 'e', 'l', 'l', 'o'};
  const ByteVector aad = {'c', 'a', 'l', 'l'};
  const ByteVector nonce = XChaCha20Poly1305::RandomNonce();
  ASSERT_EQ(nonce.size(), XChaCha20Poly1305::kNonceBytes);
  auto sealed = XChaCha20Poly1305::Seal(kKey, plain, aad, nonce);
  ASSERT_TRUE(static_cast<bool>(sealed)) << sealed.error().message;
  EXPECT_EQ(sealed->ciphertext.size(), plain.size() + XChaCha20Poly1305::kTagBytes);
  auto opened = XChaCha20Poly1305::Open(kKey, *sealed, aad);
  ASSERT_TRUE(static_cast<bool>(opened));
  EXPECT_EQ(*opened, plain);

  EXPECT_FALSE(XChaCha20Poly1305::Open(kKey, *sealed, ByteVector{'x'})) << "another aad";
  auto tampered = *sealed;
  tampered.ciphertext[0] ^= 0x01;
  EXPECT_FALSE(XChaCha20Poly1305::Open(kKey, tampered, aad)) << "an altered ciphertext";
}

// A known answer: the same key, nonce, plaintext and aad seal to the same bytes on every build — the
// ciphertext is on the wire (pp-browser's messages and media frames). Cross-checked with PyNaCl.
TEST(XChaCha20Poly1305Test, KnownAnswer) {
  const ByteVector nonce(XChaCha20Poly1305::kNonceBytes, 0x22);
  auto sealed = XChaCha20Poly1305::Seal(kKey, ByteVector{0x01, 0x02, 0x03}, ByteVector{0x04}, nonce);
  ASSERT_TRUE(static_cast<bool>(sealed));
  EXPECT_EQ(BytesToHex(sealed->ciphertext), "8265e4c4dc3af66863a240a8098f1c7bf35e48");
}

TEST(XChaCha20Poly1305Test, RejectsWrongSizes) {
  const ByteVector nonce = XChaCha20Poly1305::RandomNonce();
  EXPECT_FALSE(XChaCha20Poly1305::Seal(ByteVector(16, 0x00), ByteVector{1}, {}, nonce));
  EXPECT_FALSE(XChaCha20Poly1305::Seal(kKey, ByteVector{1}, {}, ByteVector(12, 0x00)));
}

} // namespace
} // namespace pp
