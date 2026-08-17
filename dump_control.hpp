#pragma once

#include "includes.hpp"

namespace DumpControl
{
  struct recovery_options_t
  {
    double target_coverage = 100.0;
    std::uint32_t retry_delay_ms = 250;
    std::uint32_t max_stalled_passes = 0;
    bool use_partial_store = true;
    std::string partial_store_path;
  };

  inline std::atomic_bool stop_requested = false;
  inline recovery_options_t recovery_options{};

  inline void request_stop()
  {
    stop_requested.store(true, std::memory_order_relaxed);
  }

  inline bool should_stop()
  {
    return stop_requested.load(std::memory_order_relaxed);
  }
}
