#include "crypto/AlgId.h"

#include "crypto/Aead.h"
#include "crypto/MlDsa.h"
#include "crypto/MlKem.h"

#include <gtest/gtest.h>

#include <iterator>
#include <set>
#include <utility>

namespace pp {
namespace {

// SIGNED_FORMATS § 1.3: today's `1`s stay, ids count per kind, sha2-256 is hash 2.
TEST(AlgIdTest, TheRegistryIsTheDesignsTable) {
  struct Row {
    AlgKind kind;
    uint8_t id;
    std::string_view name;
  };
  const Row want[] = {
      {AlgKind::kSignature, 1, "ml-dsa-65"},     {AlgKind::kKem, 1, "ml-kem-768"},
      {AlgKind::kAead, 1, "xchacha20-poly1305"}, {AlgKind::kHash, 1, "blake2b-256"},
      {AlgKind::kHash, 2, "sha2-256"},           {AlgKind::kKdf, 1, "hkdf-sha256"},
  };
  ASSERT_EQ(AlgRegistry().size(), std::size(want));
  for (size_t i = 0; i < std::size(want); ++i) {
    EXPECT_EQ(AlgRegistry()[i].kind, want[i].kind) << i;
    EXPECT_EQ(AlgRegistry()[i].id, want[i].id) << i;
    EXPECT_EQ(AlgRegistry()[i].name, want[i].name) << i;
    EXPECT_EQ(FindAlg(want[i].kind, want[i].id), &AlgRegistry()[i]);
    EXPECT_EQ(FindAlgByName(want[i].kind, want[i].name), &AlgRegistry()[i]);
  }
  EXPECT_EQ(kSignatureAlgMlDsa65, 1);
  EXPECT_EQ(kKemAlgMlKem768, 1);
  EXPECT_EQ(kAeadAlgXChaCha20Poly1305, 1);
  EXPECT_EQ(kHashAlgBlake2b256, 1);
  EXPECT_EQ(kHashAlgSha2_256, 2);
  EXPECT_EQ(kKdfAlgHkdfSha256, 1);
}

TEST(AlgIdTest, SizesAreTheWrappersOwn) {
  const AlgInfo* dsa = FindAlg(AlgKind::kSignature, kSignatureAlgMlDsa65);
  ASSERT_NE(dsa, nullptr);
  EXPECT_EQ(dsa->public_key_bytes, 1952u);
  EXPECT_EQ(dsa->secret_key_bytes, 4032u);
  EXPECT_EQ(dsa->signature_bytes, 3309u);
  EXPECT_EQ(dsa->seed_bytes, kMlDsa65SeedBytes);
  const AlgInfo* kem = FindAlg(AlgKind::kKem, kKemAlgMlKem768);
  ASSERT_NE(kem, nullptr);
  EXPECT_EQ(kem->public_key_bytes, 1184u);
  EXPECT_EQ(kem->secret_key_bytes, 2400u);
  EXPECT_EQ(kem->ciphertext_bytes, 1088u);
  EXPECT_EQ(kem->shared_secret_bytes, 32u);
  EXPECT_EQ(kem->seed_bytes, kMlKem768KeygenCoinsBytes);
  const AlgInfo* aead = FindAlg(AlgKind::kAead, kAeadAlgXChaCha20Poly1305);
  ASSERT_NE(aead, nullptr);
  EXPECT_EQ(aead->key_bytes, 32u);
  EXPECT_EQ(aead->nonce_bytes, 24u);
  EXPECT_EQ(aead->tag_bytes, 16u);
  EXPECT_EQ(FindAlg(AlgKind::kHash, kHashAlgBlake2b256)->digest_bytes, 32u);
  EXPECT_EQ(FindAlg(AlgKind::kHash, kHashAlgSha2_256)->digest_bytes, 32u);
}

TEST(AlgIdTest, ZeroAndUnassignedIdsAreUnknown) {
  for (const AlgKind kind : {AlgKind::kSignature, AlgKind::kKem, AlgKind::kAead, AlgKind::kHash, AlgKind::kKdf}) {
    EXPECT_EQ(FindAlg(kind, kAlgIdInvalid), nullptr) << AlgKindName(kind);
    EXPECT_EQ(FindAlg(kind, 0xff), nullptr) << AlgKindName(kind);
  }
  EXPECT_EQ(FindAlg(AlgKind::kSignature, 2), nullptr);
  EXPECT_EQ(FindAlg(AlgKind::kHash, 3), nullptr);
  // A name belongs to one kind.
  EXPECT_EQ(FindAlgByName(AlgKind::kKem, "ml-dsa-65"), nullptr);
  EXPECT_EQ(FindAlgByName(AlgKind::kSignature, "ML-DSA-65"), nullptr);
}

TEST(AlgIdTest, NamesAreUniqueAndEveryKindHasOne) {
  std::set<std::pair<AlgKind, uint8_t>> ids;
  std::set<std::string_view> names;
  for (const AlgInfo& alg : AlgRegistry()) {
    EXPECT_NE(alg.id, kAlgIdInvalid);
    EXPECT_TRUE(ids.insert({alg.kind, alg.id}).second) << alg.name;
    EXPECT_TRUE(names.insert(alg.name).second) << alg.name;
  }
}

TEST(AlgIdTest, TypedBlobRoundTrip) {
  const auto keys = MlDsa::GenerateKeyPairFromSeed(ByteVector(kMlDsa65SeedBytes, 0x42)).value();
  auto typed = EncodeTypedBlob(BlobKind::kSignaturePublicKey, kSignatureAlgMlDsa65, keys.public_key);
  ASSERT_TRUE(static_cast<bool>(typed)) << typed.error().message;
  ASSERT_EQ(typed->size(), 1953u);
  EXPECT_EQ((*typed)[0], kSignatureAlgMlDsa65);
  auto decoded = DecodeTypedBlob(BlobKind::kSignaturePublicKey, *typed);
  ASSERT_TRUE(static_cast<bool>(decoded)) << decoded.error().message;
  EXPECT_EQ(decoded->alg, FindAlg(AlgKind::kSignature, kSignatureAlgMlDsa65));
  EXPECT_EQ(decoded->body, keys.public_key);

  const auto sig = MlDsa::Sign(keys.secret_key, ByteVector{'m'}).value();
  EXPECT_EQ(EncodeTypedBlob(BlobKind::kSignature, kSignatureAlgMlDsa65, sig)->size(), 3310u);
  const auto kem = MlKem::GenerateKeyPairFromSeed(ByteVector(kMlKem768KeygenCoinsBytes, 0x11)).value();
  EXPECT_EQ(EncodeTypedBlob(BlobKind::kKemPublicKey, kKemAlgMlKem768, kem.public_key)->size(), 1185u);
  const auto encap = MlKem::Encapsulate(kem.public_key).value();
  EXPECT_EQ(EncodeTypedBlob(BlobKind::kKemCiphertext, kKemAlgMlKem768, encap.ciphertext)->size(), 1089u);
}

// The payload blob / FileCipher layout (1 ‖ nonce ‖ ciphertext ‖ tag) is already an AEAD typed blob.
TEST(AlgIdTest, TheAeadBlobIsThePayloadBlob) {
  const ByteVector key(XChaCha20Poly1305::kKeyBytes, 0x33);
  const ByteVector nonce(XChaCha20Poly1305::kNonceBytes, 0x44);
  const auto sealed = XChaCha20Poly1305::Seal(key, ByteVector{'h', 'i'}, {}, nonce).value();
  ByteVector body = sealed.nonce;
  body.insert(body.end(), sealed.ciphertext.begin(), sealed.ciphertext.end());
  auto typed = EncodeTypedBlob(BlobKind::kAeadSealed, kAeadAlgXChaCha20Poly1305, body);
  ASSERT_TRUE(static_cast<bool>(typed));
  EXPECT_EQ(typed->size(), 1u + 24u + 2u + 16u);
  auto decoded = DecodeTypedBlob(BlobKind::kAeadSealed, *typed);
  ASSERT_TRUE(static_cast<bool>(decoded));
  EXPECT_EQ(decoded->body, body);
  // Nonce and tag, no plaintext: the smallest AEAD blob.
  EXPECT_TRUE(DecodeTypedBlob(BlobKind::kAeadSealed, ByteVector(1 + 40, 0x01)));
  EXPECT_TRUE(IsMalformedTypedBlob(DecodeTypedBlob(BlobKind::kAeadSealed, ByteVector(1 + 39, 0x01)).error()));
}

TEST(AlgIdTest, UnknownAlgorithmIsNotMalformed) {
  // Unknown nonzero id: "update needed", whatever the body.
  for (const uint8_t id : {uint8_t{2}, uint8_t{0xff}}) {
    ByteVector blob(1 + kMlDsa65PublicKeyBytes, 0x01);
    blob[0] = id;
    auto decoded = DecodeTypedBlob(BlobKind::kSignaturePublicKey, blob);
    ASSERT_FALSE(static_cast<bool>(decoded)) << int(id);
    EXPECT_TRUE(IsUnknownAlgorithm(decoded.error())) << decoded.error().message;
    EXPECT_FALSE(IsMalformedTypedBlob(decoded.error()));
    auto short_body = DecodeTypedBlob(BlobKind::kKemCiphertext, ByteVector{id, 0x01, 0x02});
    ASSERT_FALSE(static_cast<bool>(short_body));
    EXPECT_TRUE(IsUnknownAlgorithm(short_body.error()));
  }
  // Known id, wrong size: malformed.
  for (const size_t size : {size_t{0}, kMlDsa65PublicKeyBytes - 1, kMlDsa65PublicKeyBytes + 1}) {
    ByteVector blob(1 + size, 0x01);
    auto decoded = DecodeTypedBlob(BlobKind::kSignaturePublicKey, blob);
    ASSERT_FALSE(static_cast<bool>(decoded)) << size;
    EXPECT_TRUE(IsMalformedTypedBlob(decoded.error())) << decoded.error().message;
    EXPECT_FALSE(IsUnknownAlgorithm(decoded.error()));
  }
  // Id 0 is invalid: malformed, whatever the body (no writer makes it, so it is not "update needed").
  for (const size_t size : {size_t{0}, size_t{2}, kMlDsa65PublicKeyBytes}) {
    ByteVector blob(1 + size, 0x01);
    blob[0] = kAlgIdInvalid;
    auto decoded = DecodeTypedBlob(BlobKind::kSignaturePublicKey, blob);
    ASSERT_FALSE(static_cast<bool>(decoded)) << size;
    EXPECT_TRUE(IsMalformedTypedBlob(decoded.error())) << decoded.error().message;
    EXPECT_FALSE(IsUnknownAlgorithm(decoded.error()));
  }
  auto empty = DecodeTypedBlob(BlobKind::kSignature, ByteVector{});
  ASSERT_FALSE(static_cast<bool>(empty));
  EXPECT_TRUE(IsMalformedTypedBlob(empty.error()));
  // An untyped error is neither.
  EXPECT_FALSE(IsUnknownAlgorithm(Error("other")));
  EXPECT_FALSE(IsMalformedTypedBlob(Error("other")));
}

TEST(AlgIdTest, AKeyOfOneKindIsNotAnotherKindsBlob) {
  // A 1185-byte KEM key typed as a signature key: id 1 is ml-dsa-65 there, and the size is wrong.
  ByteVector blob(1 + kMlKem768PublicKeyBytes, 0x05);
  blob[0] = 1;
  EXPECT_TRUE(IsMalformedTypedBlob(DecodeTypedBlob(BlobKind::kSignaturePublicKey, blob).error()));
  EXPECT_TRUE(DecodeTypedBlob(BlobKind::kKemPublicKey, blob));
  EXPECT_EQ(BlobAlgKind(BlobKind::kKemCiphertext), AlgKind::kKem);
  EXPECT_EQ(TypedBlobBodyBytes(BlobKind::kKemCiphertext, *FindAlg(AlgKind::kSignature, 1)), 0u);
}

TEST(AlgIdTest, EncodeRefusesWhatDecodeRefuses) {
  const ByteVector key(kMlDsa65PublicKeyBytes, 0x01);
  EXPECT_TRUE(IsMalformedTypedBlob(EncodeTypedBlob(BlobKind::kSignaturePublicKey, 0, key).error()));
  EXPECT_TRUE(IsUnknownAlgorithm(EncodeTypedBlob(BlobKind::kSignaturePublicKey, 2, key).error()));
  EXPECT_TRUE(IsMalformedTypedBlob(
      EncodeTypedBlob(BlobKind::kSignaturePublicKey, 1, ByteVector(kMlDsa65PublicKeyBytes - 1)).error()));
  EXPECT_TRUE(IsMalformedTypedBlob(EncodeTypedBlob(BlobKind::kAeadSealed, 1, ByteVector(39)).error()));
}

} // namespace
} // namespace pp
