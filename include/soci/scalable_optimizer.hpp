#pragma once

#include "soci/optimization.hpp"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace soci::optimization {

struct GeneticSolverConfig {
  std::size_t population{256};
  std::size_t generations{1000};
  std::size_t elitism{8};
  std::size_t tournament_size{4};
  double crossover_rate{0.9};
  double mutation_rate{0.01};
  double infeasible_penalty_multiplier{1.0};
  std::uint64_t seed{0x534f43494741ULL};
};

struct ScalableOptimizationResult : OptimizationResult {
  std::size_t generation{};
  double runtime_seconds{};
  double feasible_rate{};
  double pre_repair_feasible_rate{};
  double repair_success_rate{};
  std::vector<double> convergence_costs;
};

// Plaintext prototype for large row counts. It is intentionally separate from
// Optimizer and the encrypted exact B&B path.
class ScalableOptimizer final {
 public:
  explicit ScalableOptimizer(GeneticSolverConfig config = {});
  ScalableOptimizationResult optimize(
      const CostMatrix& costs,
      const std::string& ratio_threshold = "0.6") const;

 private:
  GeneticSolverConfig config_;
};

}  // namespace soci::optimization
