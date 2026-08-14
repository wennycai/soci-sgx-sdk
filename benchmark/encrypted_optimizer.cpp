#include "counting_secure_ops.hpp"

#include "soci/encrypted_optimizer.hpp"

#include <array>
#include <chrono>
#include <filesystem>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using Clock = std::chrono::steady_clock;
using PlainRow = std::array<std::optional<std::int64_t>, 3>;

class Authorizer final : public soci::secure::PredicateAuthorizer {
 public:
  bool authorize(const soci::secure::PredicateContext&) override {
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

std::vector<PlainRow> dataset(std::size_t rows) {
  static constexpr std::array<std::array<std::int64_t, 3>, 5> kPattern{{
      {{18, 18, 12}}, {{1, 7, 1}}, {{17, 4, 9}}, {{13, 4, 17}},
      {{3, 18, 9}},
  }};
  std::vector<PlainRow> result;
  result.reserve(rows);
  for (std::size_t i = 0; i < rows; ++i) {
    // Public deterministic pattern whose row-wise cost minima conflict with
    // the ratio constraint, exposing the relaxation's pruning strength.
    const auto& row = kPattern[i % kPattern.size()];
    result.push_back(PlainRow{row[0], row[1], row[2]});
  }
  return result;
}

struct Run {
  soci::optimization::EncryptedBranchAndBoundResult result;
  soci::benchmarking::SecureOpsCounts counts;
  std::uint64_t resolver_calls{};
  double wall_seconds{};
};

Run solve(soci::secure::RuntimeSecureOps& base_ops, soci::Runtime& runtime,
          Authorizer& authorizer,
          const soci::optimization::EncryptedOptimizationRequest& request,
          soci::optimization::EncryptedBranchAndBoundConfig config) {
  soci::benchmarking::CountingSecureOps ops(base_ops);
  Resolver resolver(runtime);
  soci::optimization::ConfidentialOptimizer optimizer(
      {ops, authorizer, resolver, std::move(config)});
  const auto start = Clock::now();
  auto result = optimizer.optimize(request);
  const auto wall = std::chrono::duration<double>(Clock::now() - start).count();
  return {std::move(result), ops.counts(), resolver.calls, wall};
}

void print(const char* mode, std::size_t rows, std::size_t requested_k,
           std::size_t actual_k, const Run& run) {
  const auto& stats = run.result.stats;
  const auto& counts = run.counts;
  const auto estimated_round_trips =
      counts.secure_compare + counts.secure_mul + run.resolver_calls;
  std::cout
      << "{\"mode\":\"" << mode << "\",\"rows\":" << rows
      << ",\"requested_k\":" << requested_k << ",\"actual_k\":"
      << actual_k << ",\"visited_nodes\":" << stats.visited_nodes
      << ",\"pruned_nodes\":" << stats.pruned_nodes
      << ",\"candidate_count\":" << stats.candidate_count
      << ",\"secure_compare\":" << counts.secure_compare
      << ",\"secure_mul\":" << counts.secure_mul
      << ",\"scalar_mul\":" << counts.scalar_mul
      << ",\"round_trips_estimate\":" << estimated_round_trips
      << ",\"preprocessing_seconds\":" << stats.preprocessing_seconds
      << ",\"search_seconds\":" << stats.search_seconds
      << ",\"total_seconds\":" << stats.total_seconds
      << ",\"wall_seconds\":" << run.wall_seconds << "}\n";
}

}  // namespace

int main(int argc, char** argv) {
  try {
    std::size_t row_count = 5;
    std::vector<std::size_t> grid_sizes{1, 3, 5, 9};
    for (int i = 1; i < argc; ++i) {
      const std::string argument = argv[i];
      if (argument == "--rows" && i + 1 < argc)
        row_count = std::stoul(argv[++i]);
      else if (argument == "--k" && i + 1 < argc)
        grid_sizes = {std::stoul(argv[++i])};
      else
        throw std::invalid_argument("usage: --rows N [--k K]");
    }
    if (row_count == 0 || row_count > 30)
      throw std::invalid_argument("rows must be in 1..30");

    const auto directory = std::filesystem::temp_directory_path() /
                           "soci-lagrangian-benchmark";
    std::filesystem::remove_all(directory);
    soci::Runtime runtime(directory.string());
    runtime.create_key("optimizer-benchmark");
    const soci::secure::NumericDomain domain{100, 30, 8, 16, 24, 32};
    soci::secure::RuntimeSecureOps base_ops(runtime, domain);
    Authorizer authorizer;

    soci::optimization::EncryptedOptimizationRequest request;
    request.threshold_scaled = 50;
    request.session_id = "benchmark-current";
    for (const auto& row : dataset(row_count)) {
      soci::optimization::EncryptedCostRow encrypted;
      for (std::size_t method = 0; method < 3; ++method)
        encrypted.methods[method] = base_ops.encryptConstant(*row[method]);
      request.costs.push_back(std::move(encrypted));
    }

    soci::optimization::EncryptedBranchAndBoundConfig current_config;
    current_config.cost_bound =
        soci::optimization::EncryptedCostBound::current_suffix;
    const auto current = solve(base_ops, runtime, authorizer, request,
                               current_config);
    print("current_suffix", row_count, 1, 1, current);

    for (const auto requested_k : grid_sizes) {
      request.session_id = "benchmark-lagrangian-" +
                           std::to_string(requested_k);
      soci::optimization::EncryptedBranchAndBoundConfig config;
      config.cost_bound = soci::optimization::EncryptedCostBound::lagrangian;
      // D=16 provides enough distinct normalized rho points for K=9 while
      // remaining inside this benchmark's declared NumericDomain.
      config.lagrangian_grid.denominator = 16;
      config.lagrangian_grid.requested_size = requested_k;
      const auto grid = soci::optimization::buildLagrangianGrid(
          domain, request.threshold_scaled, config.lagrangian_grid);
      const auto lagrangian = solve(base_ops, runtime, authorizer, request,
                                    config);
      if (lagrangian.result.feasible != current.result.feasible ||
          lagrangian.result.solution != current.result.solution)
        throw std::runtime_error("benchmark solver modes disagree");
      print("lagrangian", row_count, requested_k, grid.mu.size(), lagrangian);
    }
    std::filesystem::remove_all(directory);
    return 0;
  } catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
