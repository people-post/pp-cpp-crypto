#include "crypto/MlKem.h"

#include <gtest/gtest.h>

namespace pp {
namespace {

TEST(MlKemTest, RoundTripEncapsulation) {
  auto alice = MlKem::GenerateKeyPair();
  auto bob = MlKem::GenerateKeyPair();
  ASSERT_TRUE(static_cast<bool>(alice));
  ASSERT_TRUE(static_cast<bool>(bob));

  auto encap = MlKem::Encapsulate(bob->public_key);
  ASSERT_TRUE(static_cast<bool>(encap));
  EXPECT_EQ(encap->shared_secret.size(), kMlKem768SharedSecretBytes);
  EXPECT_EQ(encap->ciphertext.size(), kMlKem768CiphertextBytes);

  auto decap = MlKem::Decapsulate(bob->private_key, encap->ciphertext);
  ASSERT_TRUE(static_cast<bool>(decap));
  EXPECT_EQ(*decap, encap->shared_secret);
}

TEST(MlKemTest, SeededKeygenIsDeterministic) {
  ByteVector coins(kMlKem768KeygenCoinsBytes, 0x11);
  auto a = MlKem::GenerateKeyPairFromSeed(coins);
  auto b = MlKem::GenerateKeyPairFromSeed(coins);
  ASSERT_TRUE(static_cast<bool>(a));
  ASSERT_TRUE(static_cast<bool>(b));
  EXPECT_EQ(a->public_key, b->public_key);
  EXPECT_EQ(a->private_key, b->private_key);

  auto encap = MlKem::Encapsulate(a->public_key);
  ASSERT_TRUE(static_cast<bool>(encap));
  auto decap = MlKem::Decapsulate(a->private_key, encap->ciphertext);
  ASSERT_TRUE(static_cast<bool>(decap));
  EXPECT_EQ(*decap, encap->shared_secret);

  EXPECT_FALSE(static_cast<bool>(MlKem::GenerateKeyPairFromSeed(ByteVector(32, 1))));
}

} // namespace
} // namespace pp
