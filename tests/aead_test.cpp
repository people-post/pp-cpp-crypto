#include "crypto/Aead.h"
#include "crypto/SodiumUtil.h"

#include <gtest/gtest.h>
#include <sodium.h>

#include <cstdint>

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

ByteVector RandomBytes(size_t n) {
  ByteVector bytes(n);
  randombytes_buf(bytes.data(), bytes.size());
  return bytes;
}

// The wire is libsodium's construction: every size a packet can have seals to libsodium's bytes, and
// each library opens what the other sealed.
TEST(XChaCha20Poly1305Test, SealsLibsodiumsBytesAtEverySize) {
  EnsureSodiumInit();
  for (size_t size : {0u, 1u, 15u, 16u, 63u, 64u, 65u, 255u, 256u, 1100u, 1452u, 4096u, 65537u}) {
    const ByteVector key = RandomBytes(XChaCha20Poly1305::kKeyBytes);
    const ByteVector nonce = XChaCha20Poly1305::RandomNonce();
    const ByteVector plain = RandomBytes(size);
    const ByteVector aad = RandomBytes(size % 40);

    ByteVector ours(size + XChaCha20Poly1305::kTagBytes);
    auto sealed = XChaCha20Poly1305::SealInto(key, nonce, plain, aad, ours);
    ASSERT_TRUE(static_cast<bool>(sealed)) << sealed.error().message;
    ASSERT_EQ(*sealed, ours.size());

    ByteVector theirs(size + XChaCha20Poly1305::kTagBytes);
    unsigned long long theirs_len = 0;
    ASSERT_EQ(crypto_aead_xchacha20poly1305_ietf_encrypt(theirs.data(), &theirs_len, plain.data(), plain.size(),
                                                         aad.data(), aad.size(), nullptr, nonce.data(), key.data()),
              0);
    EXPECT_EQ(ours, theirs) << "size " << size;

    ByteVector opened(size);
    auto length = XChaCha20Poly1305::OpenInto(key, nonce, theirs, aad, opened);
    ASSERT_TRUE(static_cast<bool>(length)) << "size " << size;
    EXPECT_EQ(*length, size);
    EXPECT_EQ(opened, plain);

    ByteVector by_sodium(size);
    unsigned long long by_sodium_len = 0;
    EXPECT_EQ(crypto_aead_xchacha20poly1305_ietf_decrypt(by_sodium.data(), &by_sodium_len, nullptr, ours.data(),
                                                         ours.size(), aad.data(), aad.size(), nonce.data(), key.data()),
              0);
    EXPECT_EQ(by_sodium, plain);
  }
}

TEST(XChaCha20Poly1305Test, SealsAndOpensInPlace) {
  const ByteVector nonce = XChaCha20Poly1305::RandomNonce();
  const ByteVector plain = RandomBytes(1100);
  const ByteVector aad = {0x01, 0x02};
  ByteVector buffer = plain;
  buffer.resize(plain.size() + XChaCha20Poly1305::kTagBytes);
  const std::span<const uint8_t> in(buffer.data(), plain.size());
  ASSERT_TRUE(static_cast<bool>(XChaCha20Poly1305::SealInto(kKey, nonce, in, aad, buffer)));
  auto expected = XChaCha20Poly1305::Seal(kKey, plain, aad, nonce);
  ASSERT_TRUE(static_cast<bool>(expected));
  EXPECT_EQ(buffer, expected->ciphertext);

  auto length = XChaCha20Poly1305::OpenInto(kKey, nonce, buffer, aad, buffer);
  ASSERT_TRUE(static_cast<bool>(length));
  buffer.resize(*length);
  EXPECT_EQ(buffer, plain);
}

TEST(XChaCha20Poly1305Test, IntoRefusesShortBuffersAndAlteredBytes) {
  const ByteVector nonce = XChaCha20Poly1305::RandomNonce();
  const ByteVector plain = RandomBytes(100);
  ByteVector small(plain.size() + XChaCha20Poly1305::kTagBytes - 1);
  EXPECT_FALSE(XChaCha20Poly1305::SealInto(kKey, nonce, plain, {}, small));

  ByteVector sealed(plain.size() + XChaCha20Poly1305::kTagBytes);
  ASSERT_TRUE(static_cast<bool>(XChaCha20Poly1305::SealInto(kKey, nonce, plain, {}, sealed)));
  ByteVector out(plain.size() - 1);
  EXPECT_FALSE(XChaCha20Poly1305::OpenInto(kKey, nonce, sealed, {}, out)) << "a short plaintext buffer";
  out.resize(plain.size());
  EXPECT_FALSE(XChaCha20Poly1305::OpenInto(kKey, nonce, std::span<const uint8_t>(sealed.data(), 15), {}, out))
      << "shorter than a tag";
  sealed.back() ^= 0x80;
  EXPECT_FALSE(XChaCha20Poly1305::OpenInto(kKey, nonce, sealed, {}, out)) << "an altered tag";
  EXPECT_FALSE(XChaCha20Poly1305::OpenInto(ByteVector(16, 0x00), nonce, sealed, {}, out)) << "a short key";
}

} // namespace
} // namespace pp
