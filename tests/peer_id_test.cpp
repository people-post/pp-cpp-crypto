#include "crypto/MlDsa.h"
#include "crypto/PeerId.h"

#include <gtest/gtest.h>

namespace pp {
namespace {

// The golden vectors of pp-browser's MESH_IDENTITY.md: an existing node keeps its PeerId.
TEST(PeerIdTest, GoldenMlDsa65Vectors) {
  auto id42 = PeerIdFromMlDsaPublicKey(ByteVector(kMlDsa65PublicKeyBytes, 0x42));
  ASSERT_TRUE(static_cast<bool>(id42)) << id42.error().message;
  EXPECT_EQ(*id42, "QmTWkSQAcGsETogTFKrPJ3GzdHG3vP9UwXVyp2HeK9YBvP");
  auto id01 = PeerIdFromMlDsaPublicKey(ByteVector(kMlDsa65PublicKeyBytes, 0x01));
  ASSERT_TRUE(static_cast<bool>(id01)) << id01.error().message;
  EXPECT_EQ(*id01, "QmeKYz9h9AozszFqAkRzwxx4xGheEMYRVrLHuh7EMG7Bie");
}

TEST(PeerIdTest, AGeneratedKeyHasAStableQmPeerId) {
  auto keys = MlDsa::GenerateKeyPair();
  ASSERT_TRUE(static_cast<bool>(keys));
  auto a = PeerIdFromMlDsaPublicKey(keys->public_key);
  auto b = PeerIdFromMlDsaPublicKey(keys->public_key);
  ASSERT_TRUE(static_cast<bool>(a));
  EXPECT_EQ(*a, *b);
  EXPECT_EQ(a->rfind("Qm", 0), 0u) << "sha2-256 multihash";
}

TEST(PeerIdTest, OnlyAnMlDsa65KeyHasOne) {
  EXPECT_FALSE(PeerIdFromMlDsaPublicKey(ByteVector(32, 0x01)));
  EXPECT_FALSE(PeerIdFromMlDsaPublicKey(ByteVector(kMlDsa65PublicKeyBytes + 1, 0x01)));
}

} // namespace
} // namespace pp
