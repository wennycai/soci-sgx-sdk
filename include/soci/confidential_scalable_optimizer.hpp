#pragma once

#include "soci/encrypted_optimizer.hpp"
#include "soci/secure_ops.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace soci::optimization {

// Public knobs only.  The seed controls generation-zero chromosomes and the
// crossover/mutation schedule; it is never derived from ciphertext data.
struct ConfidentialScalableOptimizerConfig {
  std::size_t population{256};
  std::size_t generations{1000};
  std::size_t elitism{8};
  std::size_t tournament_size{4};
  // Zero selects the fixed public default of three repair scans per row.
  std::size_t repair_rounds{};
  double crossover_rate{0.9};
  double mutation_rate{0.01};
  // This is a public, common-scale fitness coefficient, not a cost estimate.
  std::int64_t infeasible_penalty{1};
  std::uint64_t seed{0x50454741534f4349ULL};
};

struct ConfidentialScalableOperationCounts {
  std::uint64_t encrypt_constant{};
  std::uint64_t add{};
  std::uint64_t scalar_mul{};
  std::uint64_t secure_mul{};
  std::uint64_t secure_compare{};
  std::uint64_t secure_select{};
};

struct ConfidentialScalableOptimizationStats {
  // Profiles are public schedule counts.  They never represent decrypted
  // candidate state.
  ConfidentialScalableOperationCounts per_candidate;
  ConfidentialScalableOperationCounts per_generation;
  ConfidentialScalableOperationCounts run;
  // Public-dimension estimate for a 256-population, 1000-generation run.
  // This is a planning estimate; it does not execute that run.
  ConfidentialScalableOperationCounts extrapolated_256x1000;
  std::size_t repair_rounds{};
};

// No selection, repair, ranking, or feasibility bit leaves this API.
struct ConfidentialScalableOptimizationResult {
  std::vector<std::array<secure::Ciphertext, 3>> chromosome;
  secure::Ciphertext total_cost;
  secure::Ciphertext c12;
  secure::Ciphertext c3;
  secure::Ciphertext linear;
  ConfidentialScalableOptimizationStats stats;
};

// PEGA is intentionally compiled only into the SOCI_MODE_SIM target.  It is
// a development/profiling optimizer and has no OFF, HW, EDL, or enclave path.
class ConfidentialScalableOptimizer final {
 public:
  explicit ConfidentialScalableOptimizer(
      secure::SecureOps& ops, ConfidentialScalableOptimizerConfig config = {});

  ConfidentialScalableOptimizationResult optimize(
      const EncryptedOptimizationRequest& request);

 private:
  secure::SecureOps& ops_;
  ConfidentialScalableOptimizerConfig config_;
};

}  // namespace soci::optimization
