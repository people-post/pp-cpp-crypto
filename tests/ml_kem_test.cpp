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

} // namespace
} // namespace pp
