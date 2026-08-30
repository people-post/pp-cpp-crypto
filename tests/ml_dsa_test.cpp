#include "crypto/MlDsa.h"

#include <gtest/gtest.h>

namespace pp {
namespace {

TEST(MlDsaTest, KeygenSignVerify) {
  auto keys = MlDsa::GenerateKeyPair();
  ASSERT_TRUE(static_cast<bool>(keys));
  EXPECT_EQ(keys->public_key.size(), kMlDsa65PublicKeyBytes);
  EXPECT_EQ(keys->secret_key.size(), kMlDsa65SecretKeyBytes);

  const ByteVector msg = {'h', 'e', 'l', 'l', 'o'};
  auto sig = MlDsa::Sign(keys->secret_key, msg);
  ASSERT_TRUE(static_cast<bool>(sig));
  EXPECT_EQ(sig->size(), kMlDsa65SignatureBytes);

  auto ok = MlDsa::Verify(keys->public_key, msg, *sig);
  ASSERT_TRUE(static_cast<bool>(ok));
  EXPECT_TRUE(*ok);

  ByteVector bad = *sig;
  bad[0] ^= 0x01;
  auto bad_ok = MlDsa::Verify(keys->public_key, msg, bad);
  ASSERT_TRUE(static_cast<bool>(bad_ok));
  EXPECT_FALSE(*bad_ok);
}

TEST(MlDsaTest, SeededKeygenIsDeterministic) {
  ByteVector seed(kMlDsa65SeedBytes, 0x42);
  auto a = MlDsa::GenerateKeyPairFromSeed(seed);
  auto b = MlDsa::GenerateKeyPairFromSeed(seed);
  ASSERT_TRUE(static_cast<bool>(a));
  ASSERT_TRUE(static_cast<bool>(b));
  EXPECT_EQ(a->public_key, b->public_key);
  EXPECT_EQ(a->secret_key, b->secret_key);

  const ByteVector msg = {'s', 'e', 'e', 'd'};
  auto sig = MlDsa::Sign(a->secret_key, msg);
  ASSERT_TRUE(static_cast<bool>(sig));
  auto ok = MlDsa::Verify(a->public_key, msg, *sig);
  ASSERT_TRUE(static_cast<bool>(ok));
  EXPECT_TRUE(*ok);

  EXPECT_FALSE(static_cast<bool>(MlDsa::GenerateKeyPairFromSeed(ByteVector(16, 1))));
}

} // namespace
} // namespace pp
