#include "soci/scalable_optimizer.hpp"

#include <algorithm>
#include <cassert>
#include <cmath>
#include <iostream>

using soci::optimization::CostMatrix;
using soci::optimization::GeneticSolverConfig;
using soci::optimization::ScalableOptimizer;

int main() {
  const CostMatrix costs{
      {{{"10.0"}, {"9.0"}, {"2.0"}}},
      {{{"10.0"}, std::nullopt, {"3.0"}}},
      {{std::nullopt, {"8.0"}, {"20.0"}}},
      {{{"7.0"}, {"6.0"}, std::nullopt}},
  };
  GeneticSolverConfig config;
  config.population = 64;
  config.generations = 100;
  config.elitism = 4;
  config.seed = 12345;

  const auto exact = soci::optimization::optimize_plain(costs, "0.5");
  const auto first = ScalableOptimizer(config).optimize(costs, "0.5");
  const auto second = ScalableOptimizer(config).optimize(costs, "0.5");
  assert(first.solution == second.solution);
  assert(first.total_cost == second.total_cost);
  assert(first.total_cost == exact.total_cost);
  assert(first.ratio >= 0.5 && first.ratio <= 1.0);
  assert(first.feasible_rate >= 0.0 && first.feasible_rate <= 1.0);
  assert(first.convergence_costs.size() == config.generations + 1);
  for (std::size_t i = 1; i < first.convergence_costs.size(); ++i)
    assert(first.convergence_costs[i] <= first.convergence_costs[i - 1]);
  for (std::size_t i = 0; i < first.solution.size(); ++i)
    assert(costs[i][static_cast<std::size_t>(first.solution[i] - 1)]);

  const CostMatrix needs_repair{
      {{{"10"}, std::nullopt, {"1"}}},
      {{{"10"}, std::nullopt, {"1"}}},
      {{{"10"}, std::nullopt, {"1"}}},
      {{{"10"}, std::nullopt, {"1"}}},
  };
  const auto repaired = ScalableOptimizer(config).optimize(needs_repair, "0.8");
  assert(repaired.ratio >= 0.8 && repaired.ratio < 1.0);
  assert(std::count(repaired.solution.begin(), repaired.solution.end(), 3) >= 1);
  assert(repaired.pre_repair_feasible_rate < 1.0);
  assert(repaired.repair_success_rate == 1.0);
  assert(repaired.feasible_rate == 1.0);

  const CostMatrix ratio_tie{
      {{{"6"}, std::nullopt, {"2"}}},
      {{{"2"}, std::nullopt, {"6"}}},
  };
  const auto ratio_exact = soci::optimization::optimize_plain(ratio_tie, "0.2");
  const auto ratio_ga = ScalableOptimizer(config).optimize(ratio_tie, "0.200000");
  assert(ratio_exact.solution == std::vector<int>({3, 1}));
  assert(ratio_ga.solution == ratio_exact.solution);
  assert(ratio_ga.total_cost == ratio_exact.total_cost);

  const CostMatrix lex_tie{
      {{{"1"}, {"1"}, {"3"}}},
      {{{"3"}, {"3"}, {"1"}}},
  };
  const auto lex_exact = soci::optimization::optimize_plain(lex_tie, "0.5");
  const auto lex_ga = ScalableOptimizer(config).optimize(lex_tie, " 0.500000 ");
  assert(lex_exact.solution == std::vector<int>({1, 3}));
  assert(lex_ga.solution == lex_exact.solution);

  const CostMatrix huge{{{{"999999999999999999999"}, std::nullopt, {"1"}}}};
  bool exact_range = false;
  bool ga_range = false;
  try { soci::optimization::optimize_plain(huge, "0.5"); }
  catch (const soci::optimization::OptimizationError& error) {
    exact_range = error.status() == soci::optimization::Status::numeric_range_exceeded;
  }
  try { ScalableOptimizer(config).optimize(huge, "0.5"); }
  catch (const soci::optimization::OptimizationError& error) {
    ga_range = error.status() == soci::optimization::Status::numeric_range_exceeded;
  }
  assert(exact_range && ga_range);

  bool rejected = false;
  try {
    config.population = 1;
    ScalableOptimizer invalid(config);
  } catch (const std::invalid_argument&) {
    rejected = true;
  }
  assert(rejected);
  std::cout << "scalable optimizer tests passed\n";
}
