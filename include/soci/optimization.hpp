#pragma once

#include "soci.hpp"
#include <array>
#include <optional>
#include <string>
#include <vector>

namespace soci::optimization {

using Cost = std::optional<std::string>;
using CostRow = std::array<Cost, 3>;
using CostMatrix = std::vector<CostRow>;

enum class Status {
  optimal,
  invalid_argument,
  no_feasible_solution,
  numeric_range_exceeded
};

class OptimizationError : public Error {
 public:
  OptimizationError(Status status, const std::string& message)
      : Error(message), status_(status) {}
  Status status() const noexcept { return status_; }
 private:
  Status status_;
};

struct OptimizationResult {
  double total_cost{};
  double ratio{};
  std::vector<int> solution;
  Status status{Status::optimal};
};

struct EncryptedOptimizationResult {
  std::vector<uint8_t> total_cost;
  std::vector<uint8_t> c12;
  std::vector<uint8_t> c3;
  std::vector<std::vector<uint8_t>> solution;
};

// Plain reference implementation used as an oracle for the encrypted path.
OptimizationResult optimize_plain(const CostMatrix& costs,
                                  const std::string& ratio_threshold = "0.6");
OptimizationResult optimize_csv_plain(const std::string& path,
                                      const std::string& ratio_threshold = "0.6");

class Optimizer {
 public:
  explicit Optimizer(Runtime& runtime) : runtime_(runtime) {}
  OptimizationResult optimize(const CostMatrix& costs,
                              const std::string& ratio_threshold = "0.6") const;
  OptimizationResult optimize_csv(const std::string& path,
                                  const std::string& ratio_threshold = "0.6") const;
  EncryptedOptimizationResult optimize_encrypted(
      const std::vector<std::array<std::optional<std::vector<uint8_t>>,3>>& costs,
      const std::string& ratio_threshold = "0.6") const;
 private:
  Runtime& runtime_;
};

}  // namespace soci::optimization
