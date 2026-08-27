#include "crypto/SodiumUtil.h"

#include <gtest/gtest.h>

namespace pp {
namespace {

TEST(SodiumUtilTest, HexAndBase64RoundTrip) {
  const ByteVector bytes = {0x00, 0x01, 0xfe, 0xff};
  EXPECT_EQ(BytesToHex(bytes), "0001feff");

  auto decoded_hex = HexToBytes("0001feff");
  ASSERT_TRUE(static_cast<bool>(decoded_hex));
  EXPECT_EQ(*decoded_hex, bytes);

  const std::string b64 = Base64Encode(bytes);
  auto decoded_b64 = Base64Decode(b64);
  ASSERT_TRUE(static_cast<bool>(decoded_b64));
  EXPECT_EQ(*decoded_b64, bytes);
}

} // namespace
} // namespace pp
