#include "soci/encrypted_optimizer.hpp"

#include <array>
#include <filesystem>
#include <functional>
#include <iostream>
#include <limits>
#include <optional>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using PlainRow = std::array<std::optional<std::int64_t>, 3>;

struct PlainResult {
  bool feasible{};
  std::vector<std::uint8_t> solution;
  std::int64_t total{};
  std::int64_t c12{};
  std::int64_t c3{};
};

void require(bool condition, const std::string& message) {
  if (!condition) throw std::runtime_error(message);
}

PlainResult reference(const std::vector<PlainRow>& rows,
                      std::int64_t threshold, std::int64_t scale) {
  PlainResult best;
  std::vector<std::uint8_t> solution(rows.size());
  std::function<void(std::size_t, std::int64_t, std::int64_t)> visit;
  visit = [&](std::size_t depth, std::int64_t c12, std::int64_t c3) {
    if (depth == rows.size()) {
      const auto total = c12 + c3;
      const auto linear = (scale - threshold) * c12 - threshold * c3;
      if (linear < 0 || c3 <= 0) return;
      if (!best.feasible || total < best.total ||
          (total == best.total && c12 < best.c12)) {
        best = {true, solution, total, c12, c3};
      }
      return;
    }
    for (std::size_t method = 0; method < 3; ++method) {
      if (!rows[depth][method]) continue;
      solution[depth] = static_cast<std::uint8_t>(method + 1);
      if (method < 2)
        visit(depth + 1, c12 + *rows[depth][method], c3);
      else
        visit(depth + 1, c12, c3 + *rows[depth][method]);
    }
  };
  visit(0, 0, 0);
  return best;
}

class Authorizer final : public soci::secure::PredicateAuthorizer {
 public:
  std::uint64_t calls{};
  bool authorize(const soci::secure::PredicateContext&) override {
    ++calls;
    return true;
  }
};

class Resolver final : public soci::secure::PredicateBitResolver {
 public:
  explicit Resolver(soci::Runtime& runtime) : runtime_(runtime) {}
  std::uint64_t calls{};

 private:
  bool revealFinalBit(const soci::secure::PredicateContext&,
                      const soci::secure::EncryptedBit& bit) override {
    ++calls;
    const auto value = runtime_.decrypt(bit.ciphertext().bytes);
    if (value == "0") return false;
    if (value == "1") return true;
    throw std::runtime_error("predicate did not resolve to a bit");
  }
  soci::Runtime& runtime_;
};

class Harness {
 public:
  Harness()
      : directory_(std::filesystem::temp_directory_path() /
                   "soci-encrypted-optimizer-test"),
        runtime_(prepare(directory_)),
        ops_(runtime_, {100, 8, 16, 24, 32, 32}),
        resolver_(runtime_) {
    runtime_.create_key("encrypted-optimizer");
  }

  ~Harness() { std::filesystem::remove_all(directory_); }

  soci::optimization::EncryptedBranchAndBoundResult solve(
      const std::vector<PlainRow>& rows, std::int64_t threshold,
      soci::optimization::EncryptedBranchAndBoundConfig config = {}) {
    soci::optimization::EncryptedOptimizationRequest request;
    request.threshold_scaled = threshold;
    request.session_id = "solve-" + std::to_string(++session_);
    for (const auto& row : rows) {
      soci::optimization::EncryptedCostRow encrypted;
      for (std::size_t method = 0; method < 3; ++method) {
        if (row[method]) encrypted.methods[method] = ops_.encryptConstant(*row[method]);
      }
      request.costs.push_back(std::move(encrypted));
    }
    const auto before = resolver_.calls;
    soci::optimization::ConfidentialOptimizer optimizer(
        {ops_, authorizer_, resolver_, std::move(config)});
    auto result = optimizer.optimize(request);
    require(resolver_.calls - before == result.stats.prune_predicates +
                                          result.stats.accept_predicates,
            "solver revealed something other than final PRUNE/ACCEPT bits");
    require(result.stats.prune_predicates <= result.stats.visited_nodes,
            "too many PRUNE predicates");
    require(result.stats.accept_predicates <= result.stats.candidate_count,
            "too many ACCEPT predicates");
    return result;
  }

  void compare(const std::vector<PlainRow>& rows, std::int64_t threshold,
               const std::string& label,
               soci::optimization::EncryptedBranchAndBoundConfig config = {}) {
    const auto expected = reference(rows, threshold, 100);
    const auto actual = solve(rows, threshold, std::move(config));
    require(actual.feasible == expected.feasible, label + ": feasibility");
    require(actual.solution == expected.solution, label + ": solution");
    if (!expected.feasible) {
      require(actual.solution.empty(), label + ": infeasible solution nonempty");
      return;
    }
    require(decrypt(actual.total_cost) == expected.total, label + ": total");
    require(decrypt(actual.c12) == expected.c12, label + ": c12");
    require(decrypt(actual.c3) == expected.c3, label + ": c3");
  }

  void compareBounds(const std::vector<PlainRow>& rows,
                     std::int64_t threshold, const std::string& label) {
    soci::optimization::EncryptedBranchAndBoundConfig current;
    current.cost_bound =
        soci::optimization::EncryptedCostBound::current_suffix;
    soci::optimization::EncryptedBranchAndBoundConfig zero_mu;
    zero_mu.lagrangian_grid.requested_size = 1;
    const auto current_result = solve(rows, threshold, current);
    const auto zero_mu_result = solve(rows, threshold, zero_mu);
    require(current_result.feasible == zero_mu_result.feasible,
            label + ": mu=0 feasibility differs from current suffix");
    require(current_result.solution == zero_mu_result.solution,
            label + ": mu=0 solution differs from current suffix");
    require(current_result.stats.visited_nodes ==
                zero_mu_result.stats.visited_nodes &&
            current_result.stats.pruned_nodes ==
                zero_mu_result.stats.pruned_nodes &&
            current_result.stats.candidate_count ==
                zero_mu_result.stats.candidate_count,
            label + ": mu=0 search tree differs from current suffix");
    compare(rows, threshold, label + "-lagrangian");
  }

  std::int64_t decrypt(const soci::secure::Ciphertext& value) {
    return std::stoll(runtime_.decrypt(value.bytes));
  }

  soci::secure::RuntimeSecureOps& ops() { return ops_; }

 private:
  static std::string prepare(const std::filesystem::path& directory) {
    std::filesystem::remove_all(directory);
    return directory.string();
  }

  std::filesystem::path directory_;
  soci::Runtime runtime_;
  soci::secure::RuntimeSecureOps ops_;
  Authorizer authorizer_;
  Resolver resolver_;
  std::uint64_t session_{};
};

void requireInvalid(Harness& harness,
                    soci::optimization::EncryptedOptimizationRequest request,
                    const char* message) {
  Authorizer authorizer;
  // Input validation happens before a predicate is needed. A valid engine is
  // still supplied to keep this test on the public construction path.
  class NeverResolver final : public soci::secure::PredicateBitResolver {
   private:
    bool revealFinalBit(const soci::secure::PredicateContext&,
                        const soci::secure::EncryptedBit&) override {
      throw std::runtime_error("unexpected predicate");
    }
  } resolver;
  soci::secure::PredicateEngine engine(harness.ops(), authorizer, resolver);
  soci::optimization::EncryptedBranchAndBoundSolver solver(harness.ops(), engine);
  try {
    (void)solver.solve(request);
  } catch (const soci::optimization::OptimizationError& error) {
    require(error.status() == soci::optimization::Status::invalid_argument,
            "wrong validation status");
    return;
  }
  throw std::runtime_error(message);
}

}  // namespace

int main() {
  Harness harness;
  harness.compare({PlainRow{std::nullopt, std::nullopt, 7}}, 0,
                  "single-row");
  harness.compare({PlainRow{4, 6, 9}, PlainRow{5, 2, 7}, PlainRow{8, 3, 4}},
                  50, "ordinary");
  harness.compare({PlainRow{std::nullopt, 2, 8},
                   PlainRow{3, std::nullopt, 2}}, 40, "availability");
  harness.compare({PlainRow{5, std::nullopt, std::nullopt},
                   PlainRow{std::nullopt, std::nullopt, 5}}, 50,
                  "linear-equals-zero");
  harness.compare({PlainRow{10, 1, std::nullopt},
                   PlainRow{std::nullopt, std::nullopt, 10}}, 50,
                  "more-expensive-c12-is-only-feasible");
  harness.compare({PlainRow{std::nullopt, std::nullopt, 3}}, 1,
                  "ratio-infeasible");
  harness.compare({PlainRow{1, 2, std::nullopt}}, 0, "c3-zero");
  harness.compare({PlainRow{3, std::nullopt, 2},
                   PlainRow{2, std::nullopt, 1}}, 50, "c12-tie-break");
  harness.compare({PlainRow{1, 1, 1}, PlainRow{1, 1, 1}}, 50,
                  "dfs-exact-tie");
  const auto tied = harness.solve(
      {PlainRow{1, 1, 1}, PlainRow{1, 1, 1}}, 50);
  require(tied.solution == std::vector<std::uint8_t>({1, 3}),
          "fixed DFS did not retain the first exact tie");

  const auto ratio_pruned =
      harness.solve({PlainRow{std::nullopt, std::nullopt, 2},
                     PlainRow{std::nullopt, std::nullopt, 3}}, 50);
  require(!ratio_pruned.feasible && ratio_pruned.stats.pruned_nodes > 0,
          "ratio bound did not prune");
  const auto cost_pruned = harness.solve(
      {PlainRow{1, 20, 2}, PlainRow{20, 20, 1}, PlainRow{1, 20, 2}}, 0);
  require(cost_pruned.stats.pruned_nodes > 0, "cost bound did not prune");
  const auto equal_lower_bound = harness.solve(
      {PlainRow{3, std::nullopt, 6}, PlainRow{2, std::nullopt, 5}}, 25);
  require(equal_lower_bound.feasible &&
              equal_lower_bound.solution == std::vector<std::uint8_t>({3, 1}) &&
              harness.decrypt(equal_lower_bound.total_cost) == 8 &&
              harness.decrypt(equal_lower_bound.c12) == 2,
          "cost_lower equal to incumbent was incorrectly pruned");

  harness.compareBounds(
      {PlainRow{10, 1, std::nullopt},
       PlainRow{2, std::nullopt, 7},
       PlainRow{std::nullopt, 3, 4}},
      50, "bound-mode-differential");

  std::mt19937 generator(7331);
  for (std::size_t trial = 0; trial < 36; ++trial) {
    const std::size_t n = 1 + generator() % 5;
    std::vector<PlainRow> rows(n);
    for (auto& row : rows) {
      const std::size_t first = generator() % 3;
      row[first] = 1 + generator() % 9;
      if (generator() % 3 == 0) {
        const std::size_t second = (first + 1 + generator() % 2) % 3;
        row[second] = 1 + generator() % 9;
      }
    }
    const std::array<std::int64_t, 5> thresholds{0, 25, 50, 60, 75};
    harness.compare(rows, thresholds[generator() % thresholds.size()],
                    "random-" + std::to_string(trial));
  }

  for (std::size_t trial = 0; trial < 4; ++trial) {
    const std::size_t n = 2 + generator() % 3;
    std::vector<PlainRow> rows(n);
    for (auto& row : rows) {
      for (std::size_t method = 0; method < 3; ++method)
        if (generator() % 2 == 0)
          row[method] = generator() % 10;
      if (!row[0] && !row[1] && !row[2]) row[generator() % 3] = 1;
    }
    harness.compareBounds(rows, (generator() % 4) * 20,
                          "random-bound-mode-" + std::to_string(trial));
  }

  std::vector<PlainRow> max_rows(8,
      PlainRow{std::nullopt, std::nullopt, 1});
  harness.compare(max_rows, 0, "max-rows");

  soci::optimization::EncryptedOptimizationRequest invalid;
  invalid.session_id = "validation";
  invalid.threshold_scaled = 0;
  requireInvalid(harness, invalid, "empty costs accepted");
  invalid.costs.resize(9);
  for (auto& row : invalid.costs)
    row.methods[0] = harness.ops().encryptConstant(1);
  requireInvalid(harness, invalid, "too many rows accepted");
  invalid.costs.resize(1);
  invalid.threshold_scaled = 100;
  requireInvalid(harness, invalid, "T=1 accepted");
  invalid.threshold_scaled = 0;
  invalid.costs[0].methods = {};
  requireInvalid(harness, invalid, "unavailable row accepted");
  invalid.costs[0].methods[0] = soci::secure::Ciphertext{};
  requireInvalid(harness, invalid, "empty ciphertext accepted");
  invalid.costs[0].methods[0] = harness.ops().encryptConstant(1);
  invalid.session_id = "bad/session";
  requireInvalid(harness, invalid, "invalid session accepted");

  std::cout << "Encrypted branch-and-bound differential tests passed\n";
}
