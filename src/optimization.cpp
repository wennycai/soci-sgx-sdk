#include "soci/optimization.hpp"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <fstream>
#include <functional>
#include <limits>
#include <sstream>
#include <stdexcept>

namespace soci::optimization {
namespace {
constexpr int64_t kScale = 1000000;
constexpr int64_t kSafe = std::numeric_limits<int64_t>::max() / 16;

struct Encoded {
  std::vector<std::array<std::optional<int64_t>, 3>> costs;
  int64_t threshold{};
};

[[noreturn]] void bad(Status s, const std::string& message) {
  throw OptimizationError(s, message);
}

std::string trim(std::string value) {
  auto ws = [](unsigned char c) { return std::isspace(c); };
  value.erase(value.begin(), std::find_if_not(value.begin(), value.end(), ws));
  value.erase(std::find_if_not(value.rbegin(), value.rend(), ws).base(), value.end());
  return value;
}

int64_t decimal(const std::string& input, bool threshold) {
  std::string s = trim(input);
  if (s.empty() || s[0] == '-') bad(Status::invalid_argument, "negative or empty decimal");
  if (s[0] == '+') s.erase(0, 1);
  auto dot = s.find('.');
  if (dot != std::string::npos && s.find('.', dot + 1) != std::string::npos)
    bad(Status::invalid_argument, "invalid decimal");
  std::string whole = dot == std::string::npos ? s : s.substr(0, dot);
  std::string frac = dot == std::string::npos ? "" : s.substr(dot + 1);
  if (whole.empty()) whole = "0";
  auto digits = [](const std::string& v) {
    return std::all_of(v.begin(), v.end(), [](unsigned char c) { return std::isdigit(c); });
  };
  if (!digits(whole) || !digits(frac)) bad(Status::invalid_argument, "invalid decimal");
  // Fixed point values have six decimal places. Extra zeroes are accepted;
  // non-zero discarded digits would silently change the optimization model.
  if (frac.size() > 6) {
    if (std::any_of(frac.begin() + 6, frac.end(), [](char c) { return c != '0'; }))
      bad(Status::invalid_argument, "more than six decimal places");
    frac.resize(6);
  }
  frac.append(6 - frac.size(), '0');
  try {
    size_t used = 0;
    long long w = std::stoll(whole, &used);
    if (used != whole.size() || w > (kSafe - std::stoll(frac)) / kScale)
      bad(Status::numeric_range_exceeded, "fixed-point value exceeds safe range");
    int64_t result = w * kScale + std::stoll(frac);
    if (threshold && result >= kScale)
      bad(Status::invalid_argument, "ratio_threshold must satisfy 0 <= T < 1");
    return result;
  } catch (const OptimizationError&) { throw; }
  catch (...) { bad(Status::numeric_range_exceeded, "fixed-point value exceeds safe range"); }
}

Encoded encode(const CostMatrix& matrix, const std::string& threshold) {
  if (matrix.empty()) bad(Status::invalid_argument, "cost matrix must not be empty");
  Encoded out;
  out.threshold = decimal(threshold, true);
  out.costs.reserve(matrix.size());
  __int128 max_total = 0;
  for (size_t i = 0; i < matrix.size(); ++i) {
    std::array<std::optional<int64_t>, 3> row;
    bool any = false;
    int64_t row_max = 0;
    for (size_t j = 0; j < 3; ++j) {
      if (matrix[i][j]) {
        row[j] = decimal(*matrix[i][j], false);
        row_max = std::max(row_max, *row[j]);
        any = true;
      }
    }
    if (!any) bad(Status::no_feasible_solution, "each material needs an available method");
    max_total += row_max;
    out.costs.push_back(row);
  }
  // The largest linearized ratio term is SCALE * sum(cost).
  if (max_total > kSafe || max_total * kScale > kSafe)
    bad(Status::numeric_range_exceeded, "ratio intermediate exceeds safe plaintext range");
  return out;
}

struct Solver {
  const Encoded& model;
  std::vector<int64_t> min_suffix, ratio_max_suffix;
  std::vector<int> current, best;
  int64_t best_cost = std::numeric_limits<int64_t>::max();
  int64_t best_c12{}, best_c3{};

  explicit Solver(const Encoded& value) : model(value), current(value.costs.size()) {
    size_t n = model.costs.size();
    min_suffix.assign(n + 1, 0);
    ratio_max_suffix.assign(n + 1, 0);
    for (size_t ri = n; ri-- > 0;) {
      int64_t mn = std::numeric_limits<int64_t>::max();
      int64_t mx = std::numeric_limits<int64_t>::min();
      for (int j = 0; j < 3; ++j) if (model.costs[ri][j]) {
        int64_t c = *model.costs[ri][j];
        mn = std::min(mn, c);
        int64_t contribution = j < 2 ? (kScale - model.threshold) * c
                                     : -model.threshold * c;
        mx = std::max(mx, contribution);
      }
      min_suffix[ri] = min_suffix[ri + 1] + mn;
      ratio_max_suffix[ri] = ratio_max_suffix[ri + 1] + mx;
    }
  }

  bool better_tie(int64_t c12, int64_t c3) const {
    // For feasible solutions ratio-T is non-negative. Compare exact rational
    // distances without floating point, then use lexicographic solution order.
    __int128 total = c12 + c3, old_total = best_c12 + best_c3;
    __int128 gap = (__int128)c12 * kScale - (__int128)model.threshold * total;
    __int128 old_gap = (__int128)best_c12 * kScale - (__int128)model.threshold * old_total;
    __int128 lhs = gap * old_total, rhs = old_gap * total;
    if (lhs != rhs) return lhs < rhs;
    return std::lexicographical_compare(current.begin(), current.end(), best.begin(), best.end());
  }

  void visit(size_t i, int64_t cost, int64_t c12, int64_t c3, int64_t linear) {
    if (best_cost != std::numeric_limits<int64_t>::max() && cost + min_suffix[i] > best_cost) return;
    if ((__int128)linear + ratio_max_suffix[i] < 0) return;
    if (i == model.costs.size()) {
      if (linear < 0 || c3 <= 0 || c12 + c3 <= 0) return; // ratio must exist and be < 1
      if (cost < best_cost || (cost == best_cost && better_tie(c12, c3))) {
        best_cost = cost; best_c12 = c12; best_c3 = c3; best = current;
      }
      return;
    }
    // PuLP/LpProblem-like binary variables x[i,j], visited in method order so
    // the last tie-break remains deterministic.
    for (int j = 0; j < 3; ++j) if (model.costs[i][j]) {
      int64_t c = *model.costs[i][j];
      current[i] = j + 1;
      if (j < 2) visit(i + 1, cost + c, c12 + c, c3,
                       linear + (kScale - model.threshold) * c);
      else visit(i + 1, cost + c, c12, c3 + c,
                 linear - model.threshold * c);
    }
  }
};

OptimizationResult solve(const Encoded& model) {
  Solver solver(model);
  solver.visit(0, 0, 0, 0, 0);
  if (solver.best.empty()) bad(Status::no_feasible_solution, "no assignment satisfies the ratio constraint");
  OptimizationResult result;
  result.total_cost = static_cast<double>(solver.best_cost) / kScale;
  result.ratio = static_cast<double>(solver.best_c12) /
                 static_cast<double>(solver.best_c12 + solver.best_c3);
  result.solution = std::move(solver.best);
  return result;
}

CostMatrix read_csv(const std::string& path) {
  std::ifstream in(path);
  if (!in) bad(Status::invalid_argument, "cannot open CSV file");
  CostMatrix matrix;
  std::string line;
  bool first = true;
  while (std::getline(in, line)) {
    if (!line.empty() && line.back() == '\r') line.pop_back();
    std::vector<std::string> cells;
    std::stringstream stream(line);
    std::string cell;
    while (std::getline(stream, cell, ',')) cells.push_back(trim(cell));
    if (!line.empty() && line.back() == ',') cells.emplace_back();
    if (cells.size() != 4) bad(Status::invalid_argument, "CSV rows must contain material_id and three costs");
    if (first) {
      first = false;
      std::string h = cells[0];
      std::transform(h.begin(), h.end(), h.begin(), [](unsigned char c) { return std::tolower(c); });
      if (h == "material_id") continue;
    }
    CostRow row;
    for (int j = 0; j < 3; ++j) if (!cells[j + 1].empty()) row[j] = cells[j + 1];
    matrix.push_back(std::move(row));
  }
  return matrix;
}
}  // namespace

OptimizationResult optimize_plain(const CostMatrix& costs, const std::string& threshold) {
  return solve(encode(costs, threshold));
}

OptimizationResult optimize_csv_plain(const std::string& path, const std::string& threshold) {
  return optimize_plain(read_csv(path), threshold);
}

OptimizationResult Optimizer::optimize(const CostMatrix& costs, const std::string& threshold) const {
  Encoded model = encode(costs, threshold);
  // Encrypt the complete matrix at the boundary. The model layer retains the
  // caller-provided fixed-point coefficients (as an LP solver necessarily does)
  // but never decrypts a candidate aggregate.
  std::vector<std::array<std::optional<std::vector<uint8_t>>, 3>> encrypted(model.costs.size());
  for (size_t i = 0; i < model.costs.size(); ++i)
    for (int j = 0; j < 3; ++j)
      if (model.costs[i][j]) encrypted[i][j] = runtime_.encrypt(std::to_string(*model.costs[i][j]));
  OptimizationResult result = solve(model);

  // Only the authorized final aggregate is decrypted.
  auto encrypted_total = runtime_.encrypt("0");
  auto encrypted_c12 = runtime_.encrypt("0");
  auto encrypted_c3 = runtime_.encrypt("0");
  for (size_t i = 0; i < result.solution.size(); ++i) {
    int method = result.solution[i] - 1;
    const auto& ciphertext = *encrypted[i][method];
    encrypted_total = runtime_.add(encrypted_total, ciphertext);
    if (method < 2) encrypted_c12 = runtime_.add(encrypted_c12, ciphertext);
    else encrypted_c3 = runtime_.add(encrypted_c3, ciphertext);
  }
  auto lhs = runtime_.scalar_mul(encrypted_c12, std::to_string(kScale - model.threshold));
  auto rhs = runtime_.scalar_mul(encrypted_c3, std::to_string(model.threshold));
  bool securely_compared = false;
  try {
    auto invalid = runtime_.secure_compare(rhs, lhs); // encrypted bit: rhs > lhs
    if (runtime_.decrypt(invalid) != "0") throw Error("encrypted ratio constraint failed");
    securely_compared = true;
  } catch (const Error& error) {
    // Reference SCMP is intentionally disabled in normal builds. Production
    // protocol builds use it; normal builds retain an auditable linear witness.
    if (std::string(error.what()) != "experimental protocol disabled by default") throw;
  }
  // Homomorphic subtraction produces an encrypted feasibility witness. It is
  // part of the final authorized result and is the only ratio intermediate read.
  auto witness = runtime_.add(lhs, runtime_.scalar_mul(rhs, "-1"));
  int64_t expected = 0, expected_c12 = 0;
  for (size_t i = 0; i < result.solution.size(); ++i) {
    int64_t value = *model.costs[i][result.solution[i] - 1];
    expected += value;
    if (result.solution[i] < 3) expected_c12 += value;
  }
  if ((!securely_compared && std::stoll(runtime_.decrypt(witness)) < 0) ||
      std::stoll(runtime_.decrypt(encrypted_total)) != expected)
    throw Error("encrypted optimization verification failed");
  try {
    auto scaled_numerator = runtime_.scalar_mul(encrypted_c12, std::to_string(kScale));
    auto division = runtime_.secure_div(scaled_numerator, encrypted_total);
    int64_t ratio_fixed = std::stoll(runtime_.decrypt(division.first));
    int64_t expected_ratio = static_cast<int64_t>((__int128)kScale * expected_c12 / expected);
    if (std::llabs(ratio_fixed - expected_ratio) > 1)
      throw Error("encrypted ratio division verification failed");
  } catch (const Error& error) {
    if (std::string(error.what()) != "experimental protocol disabled by default") throw;
  }
  return result;
}

OptimizationResult Optimizer::optimize_csv(const std::string& path, const std::string& threshold) const {
  return optimize(read_csv(path), threshold);
}

EncryptedOptimizationResult Optimizer::optimize_encrypted(
    const std::vector<std::array<std::optional<std::vector<uint8_t>>,3>>& costs,
    const std::string& threshold_text) const {
  if (runtime_.mode() != SOCI_MODE_OFF)
    throw Error(
        "legacy Optimizer::optimize_encrypted is restricted to OFF mode; "
        "use ThresholdConfidentialRuntime for SIM/HW");
  if(costs.empty())bad(Status::invalid_argument,"encrypted cost matrix must not be empty");
  int64_t threshold=decimal(threshold_text,true);
  for(const auto&row:costs)if(!row[0]&&!row[1]&&!row[2])bad(Status::no_feasible_solution,"each material needs an available method");
  // Values are fixed-point costs. This public sentinel must exceed the declared
  // application range; callers are required to keep total costs below kSafe.
  const int64_t sentinel=kSafe;
  auto zero=runtime_.encrypt("0"),one=runtime_.encrypt("1");
  auto select=[&](const std::vector<uint8_t>&bit,const std::vector<uint8_t>&yes,const std::vector<uint8_t>&no){
    auto delta=runtime_.add(yes,runtime_.scalar_mul(no,"-1"));
    return runtime_.add(no,runtime_.secure_mul(bit,delta));
  };
  auto best=runtime_.encrypt(std::to_string(sentinel));
  auto best12=zero,best3=zero;
  std::vector<std::vector<uint8_t>> best_choice(costs.size(),zero);
  std::vector<int> choice(costs.size());
  std::function<void(size_t)> visit=[&](size_t row){
    if(row<costs.size()){
      for(int method=0;method<3;method++)if(costs[row][method]){choice[row]=method;visit(row+1);}return;
    }
    bool has3=false;auto total=zero,c12=zero,c3=zero;
    for(size_t i=0;i<costs.size();i++){
      const auto&value=*costs[i][choice[i]];total=runtime_.add(total,value);
      if(choice[i]<2)c12=runtime_.add(c12,value);else{c3=runtime_.add(c3,value);has3=true;}
    }
    if(!has3)return; // public assignment structure, required for ratio < 1.
    auto lhs=runtime_.scalar_mul(c12,std::to_string(kScale-threshold));
    auto rhs=runtime_.scalar_mul(c3,std::to_string(threshold));
    // feasible = Enc(lhs >= rhs) = 1 - Enc(rhs > lhs)
    auto invalid=runtime_.secure_compare(rhs,lhs);
    auto feasible=runtime_.add(one,runtime_.scalar_mul(invalid,"-1"));
    auto effective=select(feasible,total,runtime_.encrypt(std::to_string(sentinel)));
    auto better=runtime_.secure_compare(best,effective); // Enc(best > candidate)
    best=select(better,effective,best);
    best12=select(better,c12,best12);best3=select(better,c3,best3);
    for(size_t i=0;i<choice.size();i++)best_choice[i]=select(better,runtime_.encrypt(std::to_string(choice[i]+1)),best_choice[i]);
  };
  visit(0);
  return {std::move(best),std::move(best12),std::move(best3),std::move(best_choice)};
}
}  // namespace soci::optimization
