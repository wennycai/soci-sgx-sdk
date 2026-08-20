#include "structured_exact_solver.hpp"
#include <chrono>
#include <iostream>
#include <stdexcept>
#include <string>

using namespace soci::structured_exact;
int main(int argc, char** argv) try {
  if (argc < 4 || argc > 6)
    throw std::runtime_error("usage: structured-exact TSV ROWS THRESHOLD [MAX_NODES] [B1|B2]");
  const auto rows = read_tsv(argv[1], std::stoull(argv[2]));
  const auto max_nodes = argc >= 5 ? std::stoull(argv[4]) : 0;
  bool enable_lagrangian = true;
  if (argc == 6) {
    const std::string strategy = argv[5];
    if (strategy == "B1") enable_lagrangian = false;
    else if (strategy != "B2") throw std::runtime_error("strategy must be B1 or B2");
  }
  const auto result = solve(rows, parse_fixed_decimal(argv[3]), max_nodes, enable_lagrangian);
  const auto& m = result.metrics;
  std::cout << "{\"total_rows\":" << m.total_rows
            << ",\"cheapest_fast_path_hit\":" << (m.cheapest_fast_path_hit ? "true" : "false")
            << ",\"fixed_no_m3_rows\":" << m.fixed_no_m3_rows << ",\"fixed_dominated_rows\":" << m.fixed_dominated_rows
            << ",\"decision_rows\":" << m.decision_rows << ",\"baseline_G\":" << ratio_to_string(m.baseline_g)
            << ",\"required_gain_D\":" << ratio_to_string(m.required_gain_d) << ",\"nodes_visited\":" << m.nodes_visited
            << ",\"max_depth\":" << m.max_depth << ",\"cover_completion_count\":" << m.cover_completion_count
            << ",\"feasibility_prune_count\":" << m.feasibility_prune_count << ",\"cost_prune_count\":" << m.cost_prune_count
            << ",\"incumbent_update_count\":" << m.incumbent_update_count << ",\"rhs_positive_prune_count\":" << m.rhs_positive_prune_count
            << ",\"lagrangian_grid_size\":" << m.lagrangian_grid_size
            << ",\"lagrangian_bound_evaluation_count\":" << m.lagrangian_bound_evaluation_count
            << ",\"lagrangian_prune_count\":" << m.lagrangian_prune_count
            << ",\"strategy\":\"" << (enable_lagrangian ? "B2" : "B1") << "\""
            << ",\"preprocessing_runtime\":" << m.preprocessing_runtime << ",\"search_runtime\":" << m.search_runtime
            << ",\"total_runtime\":" << m.total_runtime << ",\"final_objective\":" << (result.feasible ? "\"" + fixed_to_string(result.objective) + "\"" : "null")
            << ",\"final_objective_scaled\":" << (result.feasible ? std::to_string(result.objective) : "null")
            << ",\"final_ratio\":" << (result.feasible ? ratio_to_string(result.ratio) : "null")
            << ",\"feasible\":" << (result.feasible ? "true" : "false") << ",\"optimality_status\":\"" << result.status << "\""
            << ",\"solution\":[";
  for (std::size_t i = 0; i < result.solution.size(); ++i) std::cout << (i ? "," : "") << result.solution[i];
  std::cout << "]}\n";
  if (result.status == "infeasible") return 2;
  if (result.status == "node_limit") return 3;
  return 0;
} catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
