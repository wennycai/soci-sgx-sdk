#pragma once

#include "soci/encrypted_optimizer.hpp"

#include <cstdint>
#include <memory>
#include <string>

namespace soci::optimization {

enum class ThresholdExecutionMode : std::uint8_t { sim = 1, hw = 2 };

struct ThresholdConfidentialConfig {
  std::string cp_enclave_path;
  std::string key_directory;
  std::string csp_host;
  int csp_port{};
  ThresholdExecutionMode mode{ThresholdExecutionMode::hw};
  secure::NumericDomain numeric_domain;
};

// Production Threshold wiring. Protocol and resolver implementation details
// remain private; authorization policy is always supplied by the caller.
class ThresholdConfidentialRuntime {
 public:
  ThresholdConfidentialRuntime(ThresholdConfidentialConfig config,
                               secure::PredicateAuthorizer& authorizer);
  ~ThresholdConfidentialRuntime();

  ThresholdConfidentialRuntime(const ThresholdConfidentialRuntime&) = delete;
  ThresholdConfidentialRuntime& operator=(
      const ThresholdConfidentialRuntime&) = delete;
  ThresholdConfidentialRuntime(ThresholdConfidentialRuntime&&) noexcept;
  ThresholdConfidentialRuntime& operator=(
      ThresholdConfidentialRuntime&&) noexcept;

  EncryptedBranchAndBoundResult optimize(
      const EncryptedOptimizationRequest& request);

 private:
  class Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace soci::optimization
