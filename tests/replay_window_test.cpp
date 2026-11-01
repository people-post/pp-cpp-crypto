#include "crypto/ReplayWindow.h"

#include <gtest/gtest.h>

namespace pp {
namespace {

TEST(ReplayWindowTest, EachNumberIsAcceptedOnceInOrderOrNot) {
  ReplayWindow window(4);
  EXPECT_FALSE(window.Accept(0)) << "0 is never a sequence number";
  EXPECT_TRUE(window.Accept(1));
  EXPECT_TRUE(window.Accept(3));
  EXPECT_FALSE(window.Accept(3)) << "a replay";
  EXPECT_EQ(window.LastContiguous(), 1u);
  EXPECT_TRUE(window.Accept(2));
  EXPECT_EQ(window.LastContiguous(), 3u) << "the gap closed";
  EXPECT_FALSE(window.Accept(2));
  EXPECT_FALSE(window.Accept(8)) << "beyond the window";
}

TEST(ReplayWindowTest, CatchingUpMovesTheMarkAndDropsWhatItPassed) {
  ReplayWindow window(8);
  EXPECT_TRUE(window.Accept(5));
  window.CatchUpTo(4);
  EXPECT_EQ(window.LastContiguous(), 5u) << "the pending 5 follows the caught-up 4";
  EXPECT_FALSE(window.Accept(3));
  EXPECT_TRUE(window.Accept(6));
}

} // namespace
} // namespace pp
