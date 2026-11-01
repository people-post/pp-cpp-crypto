#pragma once

#include <cstddef>
#include <cstdint>
#include <unordered_set>

namespace pp {

/**
 * Replay protection for a stream of sequence numbers that may arrive out of order: each number is accepted once,
 * within `window_size` of the last contiguous one; 0 and anything at or below the contiguous mark are refused.
 */
class ReplayWindow {
public:
  explicit ReplayWindow(size_t window_size = 32);

  bool Accept(uint64_t seq);
  uint64_t LastContiguous() const { return last_contiguous_; }
  /**
   * Everything up to `seq` is already in (state kept elsewhere says so): the window moves there. A window lives in
   * memory; after a restart it starts at 0 while the persisted state does not.
   */
  void CatchUpTo(uint64_t seq);

private:
  size_t window_size_;
  uint64_t last_contiguous_ = 0;
  std::unordered_set<uint64_t> pending_;
};

} // namespace pp
