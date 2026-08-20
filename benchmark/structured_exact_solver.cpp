#include "structured_exact_solver.hpp"

#include <algorithm>
#include <chrono>
#include <cctype>
#include <fstream>
#include <iomanip>
#include <limits>
#include <sstream>
#include <stdexcept>

namespace soci::structured_exact {
namespace {
using i128 = __int128_t;

// Public normalized multipliers mu=p/q, where lambda=mu/kScale in
// LB(lambda)=lambda*R+sum min(0, extra-lambda*gain).  Keeping p/q integral
// lets every node evaluate the same fixed grid without sorting decision rows.
struct Lambda { int p; int q; };
constexpr std::array<Lambda, 15> kLagrangianGrid{{
    {0, 1}, {1, 64}, {1, 32}, {1, 16}, {1, 8}, {3, 16}, {1, 4},
    {3, 8}, {1, 2}, {3, 4}, {1, 1}, {5, 4}, {3, 2}, {2, 1}, {3, 1},
}};

i128 checked_add_i128(i128 left, i128 right, const char* what) {
  i128 output;
  if (__builtin_add_overflow(left, right, &output))
    throw std::runtime_error(std::string("int128 overflow in ") + what);
  return output;
}
i128 checked_sub_i128(i128 left, i128 right, const char* what) {
  i128 output;
  if (__builtin_sub_overflow(left, right, &output))
    throw std::runtime_error(std::string("int128 overflow in ") + what);
  return output;
}
i128 checked_mul_i128(i128 left, i128 right, const char* what) {
  i128 output;
  if (__builtin_mul_overflow(left, right, &output))
    throw std::runtime_error(std::string("int128 overflow in ") + what);
  return output;
}
i128 floor_div(i128 numerator, i128 denominator) {
  if (denominator <= 0) throw std::runtime_error("nonpositive floor divisor");
  i128 quotient = numerator / denominator;
  const i128 remainder = numerator % denominator;
  if (remainder < 0) --quotient;
  return quotient;
}

std::int64_t checked_i64(i128 value, const char* what) {
  if (value < std::numeric_limits<std::int64_t>::min() ||
      value > std::numeric_limits<std::int64_t>::max())
    throw std::runtime_error(std::string("int64 overflow in ") + what);
  return static_cast<std::int64_t>(value);
}

i128 g_term(int method, std::int64_t cost, std::int64_t threshold) {
  return method == 3 ? -static_cast<i128>(threshold) * cost
                     : static_cast<i128>(kScale - threshold) * cost;
}

struct Decision { std::size_t row; std::int64_t extra; i128 gain; };
struct Dominated { std::size_t row; std::int64_t extra; i128 loss; };

class Search {
 public:
  Search(const std::vector<Row>& rows, std::vector<int> base,
         std::vector<Decision> decisions,
         std::vector<Dominated> dominated, i128 g0, i128 required,
         Metrics& metrics, std::uint64_t max_nodes, bool enable_lagrangian)
      : rows_(rows), current_(std::move(base)),
        decisions_(std::move(decisions)), dominated_(std::move(dominated)),
        g0_(g0), required_(required), metrics_(metrics), max_nodes_(max_nodes),
        enable_lagrangian_(enable_lagrangian) {
    suffix_gain_.assign(decisions_.size() + 1, 0);
    for (std::size_t i = decisions_.size(); i-- > 0;)
      suffix_gain_[i] = checked_add_i128(
          suffix_gain_[i + 1], decisions_[i].gain, "B1 suffix gain");
    metrics_.lagrangian_grid_size = enable_lagrangian_ ? kLagrangianGrid.size() : 0;
    if (enable_lagrangian_) {
      suffix_lagrangian_.assign(kLagrangianGrid.size(),
                                 std::vector<i128>(decisions_.size() + 1, 0));
      for (std::size_t grid = 0; grid < kLagrangianGrid.size(); ++grid) {
        const auto lambda = kLagrangianGrid[grid];
        for (std::size_t i = decisions_.size(); i-- > 0;) {
          const auto& d = decisions_[i];
          const i128 scaled_extra = checked_mul_i128(
              checked_mul_i128(d.extra, lambda.q, "B2 extra*q"), kScale,
              "B2 extra*q*scale");
          const i128 weighted_gain = checked_mul_i128(lambda.p, d.gain,
                                                        "B2 p*gain");
          const i128 term = std::min<i128>(0, checked_sub_i128(
              scaled_extra, weighted_gain, "B2 Lagrangian term"));
          suffix_lagrangian_[grid][i] = checked_add_i128(
              suffix_lagrangian_[grid][i + 1], term, "B2 suffix term");
        }
      }
    }
  }

  void run() {
    // A deterministic public-index incumbent: take upgrades in original row
    // order only until the cover is met.  This is not a branch reordering or
    // a heuristic prune; it merely supplies a valid upper bound to the exact
    // cost-prune rule below.
    if (required_ > 0) {
      i128 gain = 0; std::int64_t cost = 0;
      int m3 = positive_m3_count(); std::size_t used = 0;
      for (; used < decisions_.size() && gain < required_; ++used) {
        const auto& d = decisions_[used]; current_[d.row] = m12_method_[used];
        gain = checked_add_i128(gain, d.gain, "seed gain");
        cost = checked_i64(static_cast<i128>(cost) + d.extra,
                           "seed cover cost");
        if (*rows_[d.row].cost[2] > 0) --m3;
      }
      if (gain >= required_) submit(gain, cost, m3 > 0);
      for (std::size_t i = 0; i < used; ++i) current_[decisions_[i].row] = 3;
    }
    visit(0, 0, 0, positive_m3_count());
  }
  bool found() const { return found_; }
  bool limit_reached() const { return limit_reached_; }
  std::int64_t best_extra() const { return best_extra_; }
  const std::vector<int>& solution() const { return best_; }

 private:
  int positive_m3_count() const {
    int count = 0;
    for (std::size_t i = 0; i < current_.size(); ++i)
      if (current_[i] == 3 && *rows_[i].cost[2] > 0) ++count;
    return count;
  }
  void submit(i128 gain, std::int64_t extra, bool rhs) {
    std::vector<int> candidate = current_;
    std::int64_t candidate_extra = extra;
    i128 candidate_gain = gain;
    if (!rhs) {
      bool provider = false;
      std::int64_t provider_extra = 0;
      std::size_t provider_row = 0;
      for (const auto& d : dominated_) {
        if (*rows_[d.row].cost[2] <= 0) continue;
        // A dominated M3 is allowed only if it leaves the actual ratio feasible.
        if (g0_ + candidate_gain - d.loss < 0) continue;
        if (!provider || d.extra < provider_extra) {
          provider = true; provider_extra = d.extra; provider_row = d.row;
        }
      }
      if (!provider) { ++metrics_.rhs_positive_prune_count; return; }
      candidate[provider_row] = 3;
      candidate_extra = checked_i64(static_cast<i128>(candidate_extra) + provider_extra,
                                    "provider extra cost");
      candidate_gain = checked_sub_i128(
          candidate_gain, dominated_loss(provider_row), "provider gain loss");
    }
    if (g0_ + candidate_gain < 0) { ++metrics_.rhs_positive_prune_count; return; }
    if (!found_ || candidate_extra < best_extra_) {
      found_ = true; best_extra_ = candidate_extra; best_ = std::move(candidate);
      ++metrics_.incumbent_update_count;
    }
  }
  i128 dominated_loss(std::size_t row) const {
    for (const auto& d : dominated_) if (d.row == row) return d.loss;
    return 0;
  }
  i128 lagrangian_lower_bound(std::size_t depth, i128 residual) {
    if (residual <= 0) return 0;
    ++metrics_.lagrangian_bound_evaluation_count;
    i128 bound = 0;  // The mandated lambda=0 member proves LB >= 0.
    for (std::size_t grid = 0; grid < kLagrangianGrid.size(); ++grid) {
      const auto lambda = kLagrangianGrid[grid];
      const i128 numerator = checked_add_i128(
          checked_mul_i128(lambda.p, residual, "B2 p*residual"),
          suffix_lagrangian_[grid][depth], "B2 numerator");
      const i128 denominator = checked_mul_i128(lambda.q, kScale,
                                                  "B2 denominator");
      bound = std::max(bound, floor_div(numerator, denominator));
    }
    return bound;
  }
  void visit(std::size_t depth, i128 gain, std::int64_t cost, int m3_count) {
    if (limit_reached_) return;
    if (max_nodes_ != 0 && metrics_.nodes_visited >= max_nodes_) {
      limit_reached_ = true;
      return;
    }
    ++metrics_.nodes_visited;
    metrics_.max_depth = std::max(metrics_.max_depth, depth);
    // Fixed required order: cover completion, feasibility, cost, then branch.
    if (gain >= required_) {
      ++metrics_.cover_completion_count;
      submit(gain, cost, m3_count > 0);
      return;
    }
    if (gain + suffix_gain_[depth] < required_) {
      ++metrics_.feasibility_prune_count;
      return;
    }
    if (found_ && cost >= best_extra_) {
      ++metrics_.cost_prune_count;
      return;
    }
    if (found_ && enable_lagrangian_) {
      const i128 lower_bound = lagrangian_lower_bound(depth, required_ - gain);
      if (checked_add_i128(cost, lower_bound, "B2 current+bound") >= best_extra_) {
        ++metrics_.lagrangian_prune_count;
        return;
      }
    }
    if (depth == decisions_.size()) {
      ++metrics_.feasibility_prune_count;
      return;
    }
    // Public original-index order and fixed, cost-independent y=1 then y=0
    // value order.  Taking the cover branch first reaches a feasible incumbent
    // early without sorting rows or changing any exact prune.
    const auto& d = decisions_[depth];
    current_[d.row] = m12_method_[depth];
    visit(depth + 1, checked_add_i128(gain, d.gain, "branch gain"),
          checked_i64(static_cast<i128>(cost) + d.extra, "cover cost"),
          m3_count - (*rows_[d.row].cost[2] > 0 ? 1 : 0));
    current_[d.row] = 3;
    if (limit_reached_) return;
    visit(depth + 1, gain, cost, m3_count);
  }
 public:
  void set_m12_methods(std::vector<int> methods) { m12_method_ = std::move(methods); }
 private:
  const std::vector<Row>& rows_; std::vector<int> current_;
  std::vector<Decision> decisions_; std::vector<Dominated> dominated_; i128 g0_, required_;
  Metrics& metrics_; std::vector<i128> suffix_gain_;
  std::vector<int> m12_method_; bool found_ = false; std::int64_t best_extra_ = 0;
  std::vector<int> best_; std::uint64_t max_nodes_ = 0; bool limit_reached_ = false;
  bool enable_lagrangian_ = true;
  std::vector<std::vector<i128>> suffix_lagrangian_;
};

std::int64_t objective_of(const std::vector<Row>& rows, const std::vector<int>& sol) {
  i128 total = 0;
  for (std::size_t i = 0; i < rows.size(); ++i) total += *rows[i].cost[sol[i] - 1];
  return checked_i64(total, "objective");
}

long double ratio_of(const std::vector<Row>& rows, const std::vector<int>& sol) {
  i128 c12 = 0, c3 = 0;
  for (std::size_t i = 0; i < rows.size(); ++i) {
    if (sol[i] == 3) c3 += *rows[i].cost[2];
    else c12 += *rows[i].cost[sol[i] - 1];
  }
  return c3 ? static_cast<long double>(c12) / static_cast<long double>(c12 + c3) : 0;
}

}  // namespace

std::int64_t parse_fixed_decimal(const std::string& text) {
  if (text.empty()) throw std::runtime_error("empty decimal");
  std::size_t p = 0; bool neg = false;
  if (text[p] == '+' || text[p] == '-') { neg = text[p++] == '-'; if (p == text.size()) throw std::runtime_error("invalid decimal"); }
  i128 whole = 0; std::size_t digits = 0;
  while (p < text.size() && std::isdigit(static_cast<unsigned char>(text[p]))) {
    whole = whole * 10 + (text[p++] - '0'); ++digits;
    if (whole > std::numeric_limits<std::int64_t>::max() / kScale) throw std::runtime_error("decimal overflow");
  }
  if (!digits) throw std::runtime_error("invalid decimal");
  std::int64_t fraction = 0; int fraction_digits = 0;
  if (p < text.size() && text[p] == '.') {
    ++p;
    while (p < text.size() && std::isdigit(static_cast<unsigned char>(text[p]))) {
      const int d = text[p++] - '0';
      if (fraction_digits < 6) fraction = fraction * 10 + d;
      else if (d != 0) throw std::runtime_error("more than six nonzero fractional digits");
      ++fraction_digits;
    }
  }
  if (p != text.size()) throw std::runtime_error("invalid decimal");
  while (fraction_digits++ < 6) fraction *= 10;
  i128 result = whole * kScale + fraction;
  if (neg) result = -result;
  return checked_i64(result, "decimal parse");
}

std::vector<Row> read_tsv(const std::string& path, std::size_t rows) {
  std::ifstream in(path); if (!in) throw std::runtime_error("cannot open TSV: " + path);
  std::vector<Row> output; std::string line;
  while (output.size() < rows && std::getline(in, line)) {
    Row row; std::stringstream fields(line); std::string cell;
    for (int method = 0; method < 3; ++method) {
      if (!std::getline(fields, cell, '\t')) continue;
      if (!cell.empty()) { const auto value = parse_fixed_decimal(cell); if (value < 0) throw std::runtime_error("negative cost"); row.cost[method] = value; }
    }
    if (std::getline(fields, cell, '\t')) throw std::runtime_error("too many TSV columns");
    output.push_back(row);
  }
  if (output.size() != rows) throw std::runtime_error("not enough TSV rows");
  return output;
}

Result solve(const std::vector<Row>& rows, std::int64_t threshold,
             std::uint64_t max_nodes, bool enable_lagrangian) {
  if (threshold < 0 || threshold >= kScale)
    throw std::runtime_error("threshold must satisfy 0 <= T < 1");
  const auto all_start = std::chrono::steady_clock::now(); Result result; result.metrics.total_rows = rows.size();
  std::vector<int> cheapest(rows.size());
  for (std::size_t i = 0; i < rows.size(); ++i) {
    int best = -1;
    for (int j = 0; j < 3; ++j) if (rows[i].cost[j] && (best < 0 || *rows[i].cost[j] < *rows[i].cost[best])) best = j;
    if (best < 0) throw std::runtime_error("row has no available method");
    cheapest[i] = best + 1;
  }
  Result cheap; cheap.solution = cheapest; cheap.objective = objective_of(rows, cheapest);
  if (validate(rows, threshold, cheap)) {
    result = cheap; result.feasible = true; result.status = "cheapest_global_optimum";
    result.metrics.total_rows = rows.size(); result.metrics.cheapest_fast_path_hit = true;
    result.metrics.lagrangian_grid_size = enable_lagrangian ? kLagrangianGrid.size() : 0;
    result.metrics.preprocessing_runtime = std::chrono::duration<double>(std::chrono::steady_clock::now() - all_start).count();
    result.metrics.total_runtime = result.metrics.preprocessing_runtime; result.ratio = ratio_of(rows, cheapest);
    validate(rows, threshold, result); return result;
  }
  std::vector<int> base(rows.size()); std::vector<Decision> decisions; std::vector<int> m12_methods;
  std::vector<Dominated> dominated;
  for (std::size_t i = 0; i < rows.size(); ++i) {
    const bool m12 = rows[i].cost[0].has_value() || rows[i].cost[1].has_value();
    const bool m3 = rows[i].cost[2].has_value();
    if (!m3) { if (!m12) throw std::runtime_error("row has no available method"); ++result.metrics.fixed_no_m3_rows; base[i] = rows[i].cost[0] && (!rows[i].cost[1] || *rows[i].cost[0] <= *rows[i].cost[1]) ? 1 : 2; continue; }
    if (!m12) { base[i] = 3; continue; }
    const int am = rows[i].cost[0] && (!rows[i].cost[1] || *rows[i].cost[0] <= *rows[i].cost[1]) ? 1 : 2;
    const auto a = *rows[i].cost[am - 1], b = *rows[i].cost[2];
    if (a <= b) {
      ++result.metrics.fixed_dominated_rows; base[i] = am;
      dominated.push_back({i, checked_i64(static_cast<i128>(b) - a, "dominance extra"),
                           static_cast<i128>(kScale - threshold) * a + static_cast<i128>(threshold) * b});
    } else {
      base[i] = 3;
      decisions.push_back({i, checked_i64(static_cast<i128>(a) - b, "decision extra"),
                           static_cast<i128>(kScale - threshold) * a + static_cast<i128>(threshold) * b});
      m12_methods.push_back(am);
    }
  }
  result.metrics.decision_rows = decisions.size();
  i128 g0 = 0;
  for (std::size_t i = 0; i < rows.size(); ++i)
    g0 = checked_add_i128(
        g0, g_term(base[i], *rows[i].cost[base[i]-1], threshold),
        "baseline G");
  result.metrics.baseline_g = static_cast<long double>(g0) / (static_cast<long double>(kScale) * kScale);
  const i128 required = g0 < 0 ? -g0 : 0;
  result.metrics.required_gain_d = static_cast<long double>(required) / (static_cast<long double>(kScale) * kScale);
  const auto base_objective = objective_of(rows, base);
  Search search(rows, base, decisions, dominated, g0, required,
                result.metrics, max_nodes, enable_lagrangian);
  search.set_m12_methods(std::move(m12_methods));
  result.metrics.preprocessing_runtime = std::chrono::duration<double>(
      std::chrono::steady_clock::now() - all_start).count();
  const auto search_start = std::chrono::steady_clock::now();
  search.run();
  result.metrics.search_runtime = std::chrono::duration<double>(std::chrono::steady_clock::now() - search_start).count();
  result.metrics.total_runtime = std::chrono::duration<double>(std::chrono::steady_clock::now() - all_start).count();
  if (!search.found()) {
    result.status = search.limit_reached() ? "node_limit" : "infeasible";
    return result;
  }
  result.solution = search.solution(); result.objective = checked_i64(static_cast<i128>(base_objective) + search.best_extra(), "final objective");
  result.feasible = true; result.status = "optimal_verified";
  std::string error; if (!validate(rows, threshold, result, &error)) throw std::runtime_error("internal validation failed: " + error);
  result.ratio = ratio_of(rows, result.solution);
  if (search.limit_reached()) result.status = "node_limit";
  return result;
}

bool validate(const std::vector<Row>& rows, std::int64_t threshold, const Result& result, std::string* error) {
  if (result.solution.size() != rows.size()) { if (error) *error = "solution size"; return false; }
  i128 g = 0, total = 0, c12 = 0, c3 = 0;
  for (std::size_t i = 0; i < rows.size(); ++i) {
    const int m = result.solution[i]; if (m < 1 || m > 3 || !rows[i].cost[m-1]) { if (error) *error = "one-hot/availability"; return false; }
    const auto cost = *rows[i].cost[m-1]; total += cost; g += g_term(m, cost, threshold);
    if (m == 3) c3 += cost; else c12 += cost;
  }
  if (c3 <= 0) { if (error) *error = "rhs_positive"; return false; }
  if (g < 0) { if (error) *error = "ratio"; return false; }
  if (total != result.objective) { if (error) *error = "objective"; return false; }
  return true;
}

std::string fixed_to_string(std::int64_t value) {
  const bool negative = value < 0; const std::uint64_t magnitude = negative ? static_cast<std::uint64_t>(-(value + 1)) + 1 : value;
  std::ostringstream out; out << (negative ? "-" : "") << magnitude / kScale << '.' << std::setw(6) << std::setfill('0') << magnitude % kScale; return out.str();
}
std::string ratio_to_string(long double value) { std::ostringstream out; out << std::fixed << std::setprecision(12) << static_cast<double>(value); return out.str(); }

std::int64_t floor_div_for_test(std::int64_t numerator, std::int64_t denominator) {
  return checked_i64(floor_div(numerator, denominator), "test floor division");
}

std::int64_t lagrangian_lower_bound_for_test(
    const std::vector<std::int64_t>& extras,
    const std::vector<std::int64_t>& gains,
    std::int64_t residual, std::size_t depth) {
  if (extras.size() != gains.size() || depth > extras.size() || residual < 0)
    throw std::runtime_error("invalid B2 test bound input");
  i128 best = 0;
  for (const auto lambda : kLagrangianGrid) {
    i128 numerator = checked_mul_i128(lambda.p, residual, "test B2 p*residual");
    for (std::size_t i = depth; i < extras.size(); ++i) {
      const i128 term = checked_sub_i128(
          checked_mul_i128(checked_mul_i128(extras[i], lambda.q,
                                             "test B2 extra*q"), kScale,
                            "test B2 extra*q*scale"),
          checked_mul_i128(lambda.p, gains[i], "test B2 p*gain"),
          "test B2 term");
      if (term < 0) numerator = checked_add_i128(numerator, term,
                                                   "test B2 numerator");
    }
    best = std::max(best, floor_div(numerator,
                                    checked_mul_i128(lambda.q, kScale,
                                                     "test B2 denominator")));
  }
  return checked_i64(best, "test B2 lower bound");
}

}  // namespace soci::structured_exact
