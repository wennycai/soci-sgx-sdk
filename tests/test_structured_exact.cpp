#include "structured_exact_solver.hpp"

#include <cassert>
#include <iostream>
#include <stdexcept>

using namespace soci::structured_exact;
static Row row(std::optional<std::int64_t> a, std::optional<std::int64_t> b,
               std::optional<std::int64_t> c) { return {{{a, b, c}}}; }
static std::int64_t n(long long whole) { return whole * kScale; }
static void check(const std::vector<Row>& rows, const char* threshold,
                  bool feasible, std::int64_t objective) {
  const auto result = solve(rows, parse_fixed_decimal(threshold)); std::string why;
  assert(result.feasible == feasible); if (feasible) { assert(result.objective == objective); assert(validate(rows, parse_fixed_decimal(threshold), result, &why)); }
}
static std::optional<std::int64_t> brute(const std::vector<Row>& rows, std::int64_t threshold) {
  std::optional<std::int64_t> best;
  const std::size_t choices = 1ULL << (2 * rows.size());
  for (std::size_t packed = 0; packed < choices; ++packed) {
    std::size_t x = packed; std::vector<int> solution(rows.size()); bool available = true;
    for (std::size_t i = 0; i < rows.size(); ++i) { solution[i] = static_cast<int>(x & 3) + 1; x >>= 2; if (solution[i] > 3 || !rows[i].cost[solution[i]-1]) available = false; }
    if (!available) continue;
    Result candidate; candidate.solution = solution;
    std::int64_t total = 0;
    for (std::size_t i = 0; i < rows.size(); ++i)
      total += *rows[i].cost[solution[i]-1];
    candidate.objective = total;
    if (validate(rows, threshold, candidate) && (!best || candidate.objective < *best)) best = candidate.objective;
  }
  return best;
}
static std::optional<std::int64_t> brute_residual(const std::vector<std::int64_t>& extra,
                                                  const std::vector<std::int64_t>& gain,
                                                  std::int64_t residual, std::size_t depth) {
  std::optional<std::int64_t> best;
  const std::size_t remaining = extra.size() - depth;
  for (std::size_t mask = 0; mask < (1ULL << remaining); ++mask) {
    std::int64_t cost = 0, covered = 0;
    for (std::size_t j = 0; j < remaining; ++j) if (mask & (1ULL << j)) {
      cost += extra[depth + j]; covered += gain[depth + j];
    }
    if (covered >= residual && (!best || cost < *best)) best = static_cast<std::int64_t>(cost);
  }
  return best;
}
int main() {
  // Cheapest M1/M2/M3 tie order and strict global-optimum fast path.
  { auto rows = std::vector<Row>{row(n(2), n(2), n(1)), row(n(2), n(2), n(2))};
    const auto r = solve(rows, n(0)); assert(r.metrics.cheapest_fast_path_hit); assert(r.solution[1] == 1); }
  // No decisions: a dominated provider is required and feasible.
  check({row(n(10), {}, {}), row(n(4), {}, n(6))}, "0.5", true, n(16));
  // Exactly one final M3 remains after cover upgrades.
  check({row(n(10), {}, {}), row(n(20), {}, n(10)), row(n(20), {}, n(10))}, "0.5", true, n(40));
  // All upgrades need a dominated M3 provider; the provider must preserve G.
  check({row(parse_fixed_decimal("0.5"), {}, {}), row(0, {}, n(1)),
         row(parse_fixed_decimal("1.1"), {}, n(1)), row(parse_fixed_decimal("1.1"), {}, n(1))},
        "0.7", true, parse_fixed_decimal("3.7"));
  // No legal M3 provider leaves the original model infeasible.
  check({row(n(1), {}, n(100))}, "0.9", false, 0);
  // A zero-cost M3 satisfies neither the benchmark's C3 > 0 validator nor a
  // positive-denominator completion.
  check({row(n(1), {}, 0)}, "0.5", false, 0);
  // M1 tie recovery preference.
  { auto rows = std::vector<Row>{row(n(4), {}, {}), row(n(5), n(5), n(1)), row(n(5), {}, n(1))};
    const auto r = solve(rows, parse_fixed_decimal("0.9")); assert(r.solution[1] == 1); }
  // Differential against exhaustive one-hot enumeration on a compact fixture.
  { auto rows = std::vector<Row>{row(n(3), n(4), n(1)), row(n(2), {}, n(3)), row(n(7), n(2), n(1))};
    for (const char* t : {"0.5", "0.7", "0.8"}) {
      const auto exact = brute(rows, parse_fixed_decimal(t));
      const auto b1 = solve(rows, parse_fixed_decimal(t), 0, false);
      const auto b2 = solve(rows, parse_fixed_decimal(t), 0, true);
      assert(exact.has_value() == b1.feasible && b1.feasible == b2.feasible);
      assert(b1.metrics.lagrangian_grid_size == 0);
      assert(b2.metrics.lagrangian_grid_size == 15);
      if (exact) assert(*exact == b1.objective && b1.objective == b2.objective);
    } }
  // B2's floor must round negative values down, not toward C++'s zero.
  assert(floor_div_for_test(-1, 2) == -1);
  assert(floor_div_for_test(-2, 2) == -1);
  assert(floor_div_for_test(-3, 2) == -2);
  assert(floor_div_for_test(6, 3) == 2);
  // Every depth/residual lower bound is no larger than exhaustive residual
  // cover cost.  Gains use G-numerator units (one cost unit is kScale).
  { const std::vector<std::int64_t> extra{7, 5, 4};
    const std::vector<std::int64_t> gain{3 * kScale, 2 * kScale, kScale};
    const std::vector<std::int64_t> residuals{
        1, kScale, kScale + 1, 2 * kScale, 3 * kScale,
        4 * kScale, 5 * kScale, 6 * kScale};
    for (std::size_t depth = 0; depth <= extra.size(); ++depth)
      for (const auto r : residuals) {
        const auto exact = brute_residual(extra, gain, r, depth);
        const auto lb = lagrangian_lower_bound_for_test(extra, gain, r, depth);
        if (exact) assert(lb <= *exact);
      }
  }
  // At the root, B2's grid lower bound equals the deterministic incumbent
  // extra cost.  Equality is a safe prune (no strictly better answer exists).
  { const auto rows = std::vector<Row>{row({}, {}, n(4)), row(n(4), {}, n(1))};
    const auto b1 = solve(rows, parse_fixed_decimal("0.5"), 0, false);
    const auto b2 = solve(rows, parse_fixed_decimal("0.5"), 0, true);
    assert(b1.objective == n(8) && b2.objective == b1.objective);
    assert(b2.metrics.lagrangian_prune_count == 1);
  }
  // Equality is safe for the solver's >= incumbent prune: this public-grid
  // point (mu=1) recovers the exact one-item residual cost.
  assert(lagrangian_lower_bound_for_test({1}, {kScale}, kScale) == 1);
  // The diagnostic node limit must never claim optimality.
  { auto rows = std::vector<Row>{row(n(10), {}, {}), row(n(20), {}, n(10)), row(n(20), {}, n(10))};
    const auto r = solve(rows, parse_fixed_decimal("0.5"), 1);
    assert(r.status == "node_limit");
  }
  bool rejected_one = false;
  try { (void)solve({row(n(1), {}, n(1))}, parse_fixed_decimal("1")); }
  catch (const std::runtime_error&) { rejected_one = true; }
  assert(rejected_one);
  bool rejected_overflow = false;
  try { (void)parse_fixed_decimal("9223372036854.775808"); }
  catch (const std::runtime_error&) { rejected_overflow = true; }
  assert(rejected_overflow);
  bool rejected_bound_input = false;
  try { (void)lagrangian_lower_bound_for_test({1}, {1}, -1); }
  catch (const std::runtime_error&) { rejected_bound_input = true; }
  assert(rejected_bound_input);
  std::cout << "structured exact unit tests passed\n";
}
