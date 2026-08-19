#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cmath>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <optional>
#include <regex>
#include <sstream>
#include <string>
#include <sys/types.h>
#include <unistd.h>
#include <vector>

struct Row { std::array<std::optional<double>, 3> cost; };

static std::vector<Row> read_tsv(const std::string& path, std::size_t rows) {
  std::ifstream in(path); if (!in) throw std::runtime_error("cannot open TSV");
  std::vector<Row> out; std::string line;
  while (out.size() < rows && std::getline(in, line)) {
    std::stringstream ss(line); std::string cell; Row row;
    for (int j = 0; j < 3; ++j) {
      if (!std::getline(ss, cell, '\t') || cell.empty()) continue;
      row.cost[j] = std::stod(cell);
    }
    out.push_back(row);
  }
  if (out.size() != rows) throw std::runtime_error("not enough TSV rows");
  return out;
}

static bool feasible(const std::vector<Row>& rows, double threshold,
                     double& total, std::vector<int>* solution = nullptr,
                     double* ratio = nullptr) {
  long double lhs = 0, rhs = 0; total = 0;
  for (const auto& row : rows) {
    int best = -1;
    for (int j = 0; j < 3; ++j)
      if (row.cost[j] && (best < 0 || *row.cost[j] < *row.cost[best])) best = j;
    if (best < 0) return false;
    if (solution) solution->push_back(best + 1);
    total += *row.cost[best];
    if (best < 2) lhs += *row.cost[best]; else rhs += *row.cost[best];
  }
  if (ratio) *ratio = rhs > 0 ? static_cast<double>(lhs / (lhs + rhs)) : 0.0;
  return rhs > 0 && lhs * (1.0L - threshold) >= rhs * threshold;
}

static std::string lp_path() {
  const char* dir = std::getenv("SOCI_CBC_TMPDIR");
  const std::string base = dir && *dir ? dir : "/tmp";
  return base + "/soci_cbc_" + std::to_string(static_cast<long long>(getpid()));
}

int main(int argc, char** argv) try {
  if (argc < 4 || argc > 5) throw std::runtime_error("usage: cbc-baseline TSV ROWS THRESHOLD [TIMEOUT_SECONDS]");
  const auto rows = read_tsv(argv[1], std::stoull(argv[2]));
  const double threshold = std::stod(argv[3]);
  const int timeout_seconds = argc == 5 ? std::stoi(argv[4]) : 60;
  if (timeout_seconds <= 0) throw std::runtime_error("timeout must be positive");
  const auto start = std::chrono::steady_clock::now();
  std::size_t variables = 0;
  for (const auto& row : rows) for (const auto& cost : row.cost) if (cost) ++variables;
  double cheapest_total = 0;
  double cheapest_ratio = 0;
  std::vector<int> cheapest_solution;
  const bool cheapest_feasible = feasible(rows, threshold, cheapest_total,
                                          &cheapest_solution, &cheapest_ratio);
  if (cheapest_feasible) {
    const auto seconds = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - start).count();
    std::cout << std::setprecision(12) << "{\"variables\":" << variables
              << ",\"cheapest_feasible\":true,\"cheapest_runtime_seconds\":" << seconds
              << ",\"cbc_runtime_seconds\":0,\"total_runtime_seconds\":" << seconds
              << ",\"total_cost\":" << cheapest_total
              << ",\"ratio\":" << cheapest_ratio
              << ",\"solution\":[";
    for (std::size_t i = 0; i < cheapest_solution.size(); ++i)
      std::cout << (i ? "," : "") << cheapest_solution[i];
    std::cout << "],\"cbc_nodes\":0,\"lp_iterations\":0,\"optimality_status\":\"cheapest_global_optimum\"}\n";
    return 0;
  }
  const std::string base = lp_path(), lp = base + ".lp", sol = base + ".sol", log = base + ".log";
  {
    std::ofstream out(lp); if (!out) throw std::runtime_error("cannot write LP");
    out << "Minimize\n obj:";
    for (std::size_t i = 0; i < rows.size(); ++i)
      for (int j = 0; j < 3; ++j) if (rows[i].cost[j])
        out << " + " << *rows[i].cost[j] << " x_" << i << '_' << j;
    out << "\nSubject To\n";
    for (std::size_t i = 0; i < rows.size(); ++i) {
      out << " one_" << i << ":";
      for (int j = 0; j < 3; ++j) if (rows[i].cost[j]) out << " + x_" << i << '_' << j;
      out << " = 1\n";
    }
    // The ratio semantics require a non-empty denominator (method 3).
    out << " rhs_positive:";
    for (std::size_t i = 0; i < rows.size(); ++i)
      if (rows[i].cost[2]) out << " + x_" << i << "_2";
    out << " >= 1\n";
    out << " ratio:";
    for (std::size_t i = 0; i < rows.size(); ++i) for (int j = 0; j < 3; ++j)
      if (rows[i].cost[j]) out << " + " << ((j < 2 ? 1.0 - threshold : -threshold) * *rows[i].cost[j]) << " x_" << i << '_' << j;
    out << " >= 0\nBinary\n";
    for (std::size_t i = 0; i < rows.size(); ++i) for (int j = 0; j < 3; ++j)
      if (rows[i].cost[j]) out << " x_" << i << '_' << j;
    out << "\nEnd\n";
  }
  const char* cbc = std::getenv("SOCI_CBC_COMMAND");
  const std::string runner = cbc && *cbc ? cbc : "cbc";
  const auto cbc_start = std::chrono::steady_clock::now();
  const std::string command = runner + " " + lp + " seconds " + std::to_string(timeout_seconds) +
                              " solve solu " + sol + " >" + log + " 2>&1";
  const int rc = std::system(command.c_str());
  const double cbc_seconds = std::chrono::duration<double>(
      std::chrono::steady_clock::now() - cbc_start).count();
  double objective = 0;
  bool found_objective = false;
  std::uint64_t cbc_nodes = 0, lp_iterations = 0;
  bool timed_out = false;
  std::vector<int> selected(rows.size(), -1);
  std::string line;
  std::ifstream input(sol);
  if (!input) throw std::runtime_error("CBC solution missing");
  while (std::getline(input, line)) {
    const auto marker = line.find("objective value");
    if (marker != std::string::npos) {
      objective = std::stod(line.substr(marker + 15));
      found_objective = true;
      continue;
    }
    std::stringstream variable(line);
    std::string index, name;
    double value = 0;
    if (!(variable >> index >> name >> value) || name.rfind("x_", 0) != 0 || value < 0.5)
      continue;
    std::size_t split = name.find('_', 2);
    if (split == std::string::npos) continue;
    const auto row = std::stoull(name.substr(2, split - 2));
    const auto method = std::stoi(name.substr(split + 1));
    if (row >= rows.size() || method < 0 || method >= 3 || selected[row] != -1)
      throw std::runtime_error("CBC solution has invalid or duplicate selection");
    selected[row] = method;
  }
  std::ifstream log_input(log);
  while (std::getline(log_input, line)) {
    if (line.find("Stopped on time limit") != std::string::npos ||
        line.find("Exiting on maximum time") != std::string::npos) timed_out = true;
    std::smatch match;
    if (std::regex_search(line, match, std::regex("took ([0-9]+) iterations and ([0-9]+) nodes"))) {
      lp_iterations = std::stoull(match[1]);
      cbc_nodes = std::stoull(match[2]);
    }
  }
  if (rc != 0 || timed_out) {
    std::remove(lp.c_str()); std::remove(sol.c_str()); std::remove(log.c_str());
    const auto seconds = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - start).count();
    std::cout << std::setprecision(12) << "{\"variables\":" << variables
              << ",\"cheapest_feasible\":false,\"cheapest_runtime_seconds\":0"
              << ",\"cbc_runtime_seconds\":" << cbc_seconds
              << ",\"total_runtime_seconds\":" << seconds
              << ",\"total_cost\":null,\"cbc_nodes\":" << cbc_nodes
              << ",\"lp_iterations\":" << lp_iterations
              << ",\"optimality_status\":\"timeout\"}\n";
    return 0;
  }
  if (!found_objective) throw std::runtime_error("CBC did not return an objective");
  long double lhs = 0, rhs = 0;
  double recomputed_total = 0;
  for (std::size_t i = 0; i < rows.size(); ++i) {
    if (selected[i] < 0 || !rows[i].cost[selected[i]])
      throw std::runtime_error("CBC solution violates one-hot row selection");
    const double cost = *rows[i].cost[selected[i]];
    recomputed_total += cost;
    if (selected[i] < 2) lhs += cost; else rhs += cost;
  }
  if (rhs <= 0 || lhs * (1.0L - threshold) + 1e-9L < rhs * threshold)
    throw std::runtime_error("CBC solution violates ratio threshold");
  const double tolerance = 1e-6 * std::max(1.0, std::abs(objective));
  if (std::abs(recomputed_total - objective) > tolerance)
    throw std::runtime_error("CBC objective does not match recomputed total");
  std::remove(lp.c_str()); std::remove(sol.c_str()); std::remove(log.c_str());
  const auto seconds = std::chrono::duration<double>(
      std::chrono::steady_clock::now() - start).count();
  std::cout << std::setprecision(12) << "{\"variables\":" << variables
            << ",\"cheapest_feasible\":false,\"cbc_runtime_seconds\":" << cbc_seconds
            << ",\"total_runtime_seconds\":" << seconds
            << ",\"total_cost\":" << recomputed_total
            << ",\"ratio\":" << static_cast<double>(lhs / (lhs + rhs))
            << ",\"solution\":[";
  for (std::size_t i = 0; i < selected.size(); ++i)
    std::cout << (i ? "," : "") << selected[i] + 1;
  std::cout << "],\"cbc_nodes\":" << cbc_nodes
            << ",\"lp_iterations\":" << lp_iterations
            << ",\"optimality_status\":\"optimal_verified\"}\n";
  return 0;
} catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
