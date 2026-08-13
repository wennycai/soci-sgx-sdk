#pragma once

#include "soci/optimization.hpp"
#include "soci/predicate_engine.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace soci::optimization {

struct EncryptedCostRow {
  // Available costs must represent non-negative values within NumericDomain.
  // The solver cannot decrypt ciphertexts to validate either property.
  std::array<std::optional<secure::Ciphertext>, 3> methods;
};

struct EncryptedOptimizationRequest {
  std::vector<EncryptedCostRow> costs;
  std::int64_t threshold_scaled{};
  std::string session_id;
};

struct EncryptedOptimizationStats {
  std::uint64_t visited_nodes{};
  std::uint64_t pruned_nodes{};
  std::uint64_t candidate_count{};
  std::uint64_t prune_predicates{};
  std::uint64_t accept_predicates{};
};

// The longer name avoids colliding with Optimizer's legacy encrypted facade
// result. This type belongs only to the semantic-predicate B&B core.
struct EncryptedBranchAndBoundResult {
  bool feasible{};
  std::vector<std::uint8_t> solution;

  secure::Ciphertext total_cost;
  secure::Ciphertext c12;
  secure::Ciphertext c3;
  secure::Ciphertext linear;

  EncryptedOptimizationStats stats;
};

class EncryptedBranchAndBoundSolver {
 public:
  EncryptedBranchAndBoundSolver(secure::SecureOps& ops,
                                secure::PredicateEngine& predicates)
      : ops_(ops), predicates_(predicates) {}

  EncryptedBranchAndBoundResult solve(
      const EncryptedOptimizationRequest& request);

 private:
  secure::SecureOps& ops_;
  secure::PredicateEngine& predicates_;
};

}  // namespace soci::optimization
