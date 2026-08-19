#include "soci/scalable_optimizer.hpp"

#include <algorithm>
#include <chrono>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>

namespace soci::optimization {
std::uint64_t plaintext_benchmark_visited_nodes() noexcept;
}

namespace {
soci::optimization::CostMatrix read_tsv(const std::string& path,
                                         std::size_t rows) {
  std::ifstream input(path);
  if (!input) throw std::runtime_error("cannot open input TSV");
  soci::optimization::CostMatrix result;
  std::string line;
  while (result.size() < rows && std::getline(input, line)) {
    std::stringstream stream(line);
    std::string cell;
    soci::optimization::CostRow row;
    for (std::size_t i = 0; i < 3; ++i) {
      if (!std::getline(stream, cell, '\t')) cell.clear();
      if (!cell.empty()) row[i] = cell;
    }
    result.push_back(std::move(row));
  }
  if (result.size() != rows) throw std::runtime_error("not enough TSV rows");
  return result;
}
}

int main(int argc, char** argv) try {
  if (argc < 6 || argc > 8)
    throw std::runtime_error(
        "usage: scalable-benchmark TSV ROWS POPULATION GENERATIONS SEED "
        "[THRESHOLD] [--no-exact|--exact-only]");
  const auto rows = static_cast<std::size_t>(std::stoull(argv[2]));
  std::string threshold = "0.5";
  bool threshold_seen = false, no_exact = false, exact_only = false;
  if (argc == 8 && std::string(argv[7]) != "--no-exact" &&
      std::string(argv[7]) != "--exact-only")
    throw std::runtime_error("unknown benchmark flag: " + std::string(argv[7]));
  for (int i = 6; i < argc; ++i) {
    const std::string argument = argv[i];
    if (argument == "--no-exact") no_exact = true;
    else if (argument == "--exact-only") exact_only = true;
    else if (!threshold_seen) { threshold = argument; threshold_seen = true; }
    else throw std::runtime_error("unknown or duplicate benchmark argument: " + argument);
  }
  if (no_exact && exact_only)
    throw std::runtime_error("--no-exact and --exact-only are mutually exclusive");
  const auto costs = read_tsv(argv[1], rows);
  if (exact_only) {
    const auto start = std::chrono::steady_clock::now();
    const auto exact = soci::optimization::optimize_plain(costs, threshold);
    const auto seconds = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - start).count();
    std::cout << std::setprecision(12) << "{\"rows\":" << rows
              << ",\"threshold\":" << threshold
              << ",\"exact_total_cost\":" << exact.total_cost
              << ",\"visited_nodes\":"
              << soci::optimization::plaintext_benchmark_visited_nodes()
              << ",\"exact_runtime_seconds\":" << seconds << "}\n";
    return 0;
  }
  soci::optimization::GeneticSolverConfig config;
  config.population = static_cast<std::size_t>(std::stoull(argv[3]));
  config.generations = static_cast<std::size_t>(std::stoull(argv[4]));
  config.elitism = std::min<std::size_t>(8, config.population - 1);
  config.seed = std::stoull(argv[5]);
  const auto ga = soci::optimization::ScalableOptimizer(config).optimize(
      costs, threshold);
  std::cout << std::setprecision(12) << "{\"rows\":" << rows
            << ",\"population\":" << config.population
            << ",\"generations\":" << config.generations
            << ",\"threshold\":" << threshold
            << ",\"total_cost\":" << ga.total_cost
            << ",\"ratio\":" << ga.ratio
            << ",\"generation\":" << ga.generation
            << ",\"runtime_seconds\":" << ga.runtime_seconds
            << ",\"feasible_rate\":" << ga.feasible_rate;
  std::cout << ",\"pre_repair_feasible_rate\":"
            << ga.pre_repair_feasible_rate
            << ",\"repair_success_rate\":" << ga.repair_success_rate;
  std::cout << ",\"convergence_costs\":[";
  for (std::size_t i = 0; i < ga.convergence_costs.size(); ++i) {
    if (i) std::cout << ',';
    if (rows <= 30 || i == 0 || i + 1 == ga.convergence_costs.size() ||
        i % std::max<std::size_t>(1, ga.convergence_costs.size() / 100) == 0)
      std::cout << ga.convergence_costs[i];
    else
      std::cout << "null";
  }
  std::cout << ']';
  if (rows <= 30 && !no_exact) {
    const auto start = std::chrono::steady_clock::now();
    const auto exact = soci::optimization::optimize_plain(costs, threshold);
    const auto seconds = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - start).count();
    const auto gap = (ga.total_cost - exact.total_cost) / exact.total_cost;
    std::cout << ",\"exact_total_cost\":" << exact.total_cost
              << ",\"exact_runtime_seconds\":" << seconds
              << ",\"optimality_gap\":" << gap;
  }
  std::cout << ",\"solution\":[";
  for (std::size_t i = 0; i < ga.solution.size(); ++i) {
    if (i) std::cout << ',';
    std::cout << ga.solution[i];
  }
  std::cout << "]}\n";
  return 0;
} catch (const std::exception& error) {
  std::cerr << error.what() << '\n';
  return 1;
}
