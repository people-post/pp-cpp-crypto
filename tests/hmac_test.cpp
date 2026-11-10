#include "crypto/Hmac.h"
#include "crypto/SodiumUtil.h"

#include <gtest/gtest.h>
#include <sodium.h>

#include <string>

namespace pp {
namespace {

ByteVector Bytes(const std::string& text) {
  return ByteVector(text.begin(), text.end());
}

std::string Hex(const HmacSha256::Tag& tag) {
  return BytesToHex(ByteVector(tag.begin(), tag.end()));
}

// RFC 4231 test case 2: a key shorter than the block.
TEST(HmacSha256Test, Rfc4231ShortKey) {
  EXPECT_EQ(Hex(HmacSha256::Compute(Bytes("Jefe"), Bytes("what do ya want for nothing?"))),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
}

// The wire is libsodium's crypto_auth_hmacsha256: the same tag for keys shorter than, equal to and longer than
// a block, and messages across block boundaries; one HmacSha256 reused gives the same tag every time.
TEST(HmacSha256Test, TagsAreLibsodiumsForEveryKeyAndMessageSize) {
  EnsureSodiumInit();
  for (size_t key_size : {0u, 1u, 32u, 63u, 64u, 65u, 131u}) {
    ByteVector key(key_size);
    randombytes_buf(key.data(), key.size());
    const HmacSha256 mac(key);
    for (size_t size : {0u, 1u, 40u, 55u, 56u, 64u, 119u, 120u, 1100u, 4096u}) {
      ByteVector data(size);
      randombytes_buf(data.data(), data.size());

      crypto_auth_hmacsha256_state state;
      crypto_auth_hmacsha256_init(&state, key.data(), key.size());
      crypto_auth_hmacsha256_update(&state, data.data(), data.size());
      HmacSha256::Tag theirs;
      crypto_auth_hmacsha256_final(&state, theirs.data());

      EXPECT_EQ(mac.Mac(data), theirs) << "key " << key_size << " data " << size;
      EXPECT_EQ(mac.Mac(data), theirs) << "reused, key " << key_size << " data " << size;
      EXPECT_EQ(HmacSha256::Compute(key, data), theirs);
    }
  }
}

TEST(HmacSha256Test, ACopyMacsTheSame) {
  const HmacSha256 mac(Bytes("key"));
  HmacSha256 copy = mac;
  EXPECT_EQ(copy.Mac(Bytes("x")), mac.Mac(Bytes("x")));
  copy = HmacSha256(Bytes("other"));
  EXPECT_NE(copy.Mac(Bytes("x")), mac.Mac(Bytes("x")));
}

} // namespace
} // namespace pp
