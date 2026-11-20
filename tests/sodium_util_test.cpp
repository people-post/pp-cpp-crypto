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

TEST(SodiumUtilTest, Base64UrlRoundTripsWithoutPadding) {
  const ByteVector bytes = {0xfb, 0xff, 0x00};
  const std::string encoded = Base64UrlEncode(bytes);
  EXPECT_EQ(encoded, "-_8A");
  auto decoded = Base64UrlDecode(encoded);
  ASSERT_TRUE(static_cast<bool>(decoded));
  EXPECT_EQ(*decoded, bytes);
  EXPECT_FALSE(static_cast<bool>(Base64UrlDecode("+/8A"))) << "the standard alphabet is not base64url";
}

// "" is the base64 of no bytes (RFC 4648 § 10). Decoding it must not hand libsodium the null buffer of an empty output
// vector (`sodium_base642bin` declares it nonnull: undefined behaviour, which UBSan reports).
TEST(SodiumUtilTest, EmptyBase64DecodesToNoBytes) {
  auto decoded = Base64Decode("");
  ASSERT_TRUE(static_cast<bool>(decoded)) << decoded.error().message;
  EXPECT_TRUE(decoded->empty());
  auto decoded_url = Base64UrlDecode("");
  ASSERT_TRUE(static_cast<bool>(decoded_url)) << decoded_url.error().message;
  EXPECT_TRUE(decoded_url->empty());
  EXPECT_EQ(Base64Encode({}), "");
  EXPECT_EQ(Base64UrlEncode({}), "");
  EXPECT_FALSE(static_cast<bool>(Base64Decode("="))) << "not empty: still checked";
  EXPECT_FALSE(static_cast<bool>(Base64UrlDecode("*")));
}

TEST(SodiumUtilTest, Blake2b256OfNothingIsTheKnownVector) {
  // RFC 7693 BLAKE2b with a 32-byte digest, empty input.
  EXPECT_EQ(BytesToHex(Blake2b256({})), "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8");
}

} // namespace
} // namespace pp
