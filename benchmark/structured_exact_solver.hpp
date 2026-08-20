#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace soci::structured_exact {

constexpr std::int64_t kScale = 1000000;

struct Row {
  std::array<std::optional<std::int64_t>, 3> cost;
};

struct Metrics {
  std::size_t total_rows = 0, fixed_no_m3_rows = 0, fixed_dominated_rows = 0;
  std::size_t decision_rows = 0, nodes_visited = 0, max_depth = 0;
  std::size_t cover_completion_count = 0, feasibility_prune_count = 0;
  std::size_t cost_prune_count = 0, incumbent_update_count = 0;
  std::size_t rhs_positive_prune_count = 0;
  std::size_t lagrangian_grid_size = 0;
  std::size_t lagrangian_bound_evaluation_count = 0;
  std::size_t lagrangian_prune_count = 0;
  bool cheapest_fast_path_hit = false;
  long double baseline_g = 0, required_gain_d = 0;
  double preprocessing_runtime = 0, search_runtime = 0, total_runtime = 0;
};

struct Result {
  bool feasible = false;
  std::string status;
  std::vector<int> solution;  // Methods are 1, 2, 3.
  std::int64_t objective = 0; // fixed point, kScale units
  long double ratio = 0;
  Metrics metrics;
};

std::int64_t parse_fixed_decimal(const std::string& text);
std::vector<Row> read_tsv(const std::string& path, std::size_t rows);
// max_nodes == 0 runs to an Exact terminal.  A positive limit is an opt-in
// diagnostic guard: the returned status is node_limit and must not be treated
// as an optimality proof.
Result solve(const std::vector<Row>& rows, std::int64_t threshold,
             std::uint64_t max_nodes = 0, bool enable_lagrangian = true);
bool validate(const std::vector<Row>& rows, std::int64_t threshold,
              const Result& result, std::string* error = nullptr);
std::string fixed_to_string(std::int64_t value);
std::string ratio_to_string(long double value);

// Narrow public test seam for the B2 arithmetic.  costs are fixed-point cost
// units and gains/residual are the corresponding G-numerator units.
std::int64_t lagrangian_lower_bound_for_test(
    const std::vector<std::int64_t>& extras,
    const std::vector<std::int64_t>& gains,
    std::int64_t residual, std::size_t depth = 0);
std::int64_t floor_div_for_test(std::int64_t numerator, std::int64_t denominator);

}  // namespace soci::structured_exact
