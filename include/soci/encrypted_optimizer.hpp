#pragma once

#include "soci/optimization.hpp"
#include "soci/lagrangian_relaxation.hpp"
#include "soci/predicate_engine.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <utility>
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

enum class EncryptedCostBound : std::uint8_t {
  current_suffix = 1,
  lagrangian = 2,
};

struct EncryptedBranchAndBoundConfig {
  EncryptedCostBound cost_bound{EncryptedCostBound::lagrangian};
  LagrangianGridConfig lagrangian_grid;
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
                                secure::PredicateEngine& predicates,
                                EncryptedBranchAndBoundConfig config = {})
      : ops_(ops), predicates_(predicates), config_(std::move(config)) {}

  EncryptedBranchAndBoundResult solve(
      const EncryptedOptimizationRequest& request);

 private:
  secure::SecureOps& ops_;
  secure::PredicateEngine& predicates_;
  EncryptedBranchAndBoundConfig config_;
};

struct ConfidentialOptimizerConfig {
  secure::SecureOps& ops;
  secure::PredicateAuthorizer& authorizer;
  secure::PredicateBitResolver& resolver;
  EncryptedBranchAndBoundConfig solver_config{};
};

// Policy-free facade: callers must supply both authorization and the narrowly
// scoped final-predicate resolver. The SDK never installs an allow-all policy.
// Each solve should use a unique session_id. Policy for cross-solve session-id
// reuse belongs to the caller-supplied PredicateAuthorizer.
class ConfidentialOptimizer {
 public:
  explicit ConfidentialOptimizer(ConfidentialOptimizerConfig config)
      : ops_(config.ops),
        authorizer_(config.authorizer),
        resolver_(config.resolver),
        solver_config_(std::move(config.solver_config)) {}

  EncryptedBranchAndBoundResult optimize(
      const EncryptedOptimizationRequest& request);

 private:
  secure::SecureOps& ops_;
  secure::PredicateAuthorizer& authorizer_;
  secure::PredicateBitResolver& resolver_;
  EncryptedBranchAndBoundConfig solver_config_;
};

}  // namespace soci::optimization
