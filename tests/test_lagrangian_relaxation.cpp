#include "soci/lagrangian_relaxation.hpp"
#include "lagrangian_plain_reference.hpp"

#include <algorithm>
#include <functional>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using soci::optimization::LagrangianGrid;
using soci::optimization::LagrangianGridConfig;
using soci::test_support::PlainLagrangianRow;

void require(bool condition, const std::string& message) {
  if (!condition) throw std::runtime_error(message);
}

template <typename Function>
void requireStatus(Function function, soci::optimization::Status status,
                   const std::string& message) {
  try {
    function();
  } catch (const soci::optimization::OptimizationError& error) {
    require(error.status() == status, message + ": wrong status");
    return;
  }
  throw std::runtime_error(message);
}

std::int64_t linearContribution(std::int64_t cost, std::size_t method,
                                std::int64_t threshold,
                                std::int64_t scale) {
  return cost * (method < 2 ? scale - threshold : -threshold);
}

void verifySoundness(const std::vector<PlainLagrangianRow>& rows,
                     std::int64_t threshold, std::int64_t scale,
                     const LagrangianGrid& grid) {
  std::vector<std::uint8_t> prefix;
  std::function<void(std::size_t)> visitPrefix;
  visitPrefix = [&](std::size_t depth) {
    const auto bounds =
        soci::test_support::plaintextLagrangianLowerBounds(
            rows, prefix, depth, threshold, scale, grid);
    std::vector<std::uint8_t> completion = prefix;
    completion.resize(rows.size());
    std::function<void(std::size_t, std::int64_t, std::int64_t)> complete;
    complete = [&](std::size_t row, std::int64_t cost,
                   std::int64_t linear) {
      if (row == rows.size()) {
        if (linear < 0) return;
        for (const auto bound : bounds)
          require(bound <= grid.q * cost,
                  "Lagrangian LB exceeded a feasible completion");
        return;
      }
      for (std::size_t method = 0; method < 3; ++method) {
        if (!rows[row][method]) continue;
        completion[row] = static_cast<std::uint8_t>(method + 1);
        complete(row + 1, cost + *rows[row][method],
                 linear + linearContribution(*rows[row][method], method,
                                             threshold, scale));
      }
    };
    std::int64_t prefix_cost = 0;
    std::int64_t prefix_linear = 0;
    for (std::size_t i = 0; i < depth; ++i) {
      const auto method = prefix[i] - 1;
      prefix_cost += *rows[i][method];
      prefix_linear += linearContribution(*rows[i][method], method,
                                          threshold, scale);
    }
    complete(depth, prefix_cost, prefix_linear);
    if (depth == rows.size()) return;
    for (std::size_t method = 0; method < 3; ++method) {
      if (!rows[depth][method]) continue;
      prefix.push_back(static_cast<std::uint8_t>(method + 1));
      visitPrefix(depth + 1);
      prefix.pop_back();
    }
  };
  visitPrefix(0);
}

}  // namespace

int main() {
  const soci::secure::NumericDomain domain{100, 8, 8, 16, 24, 32};
  const auto grid = soci::optimization::buildLagrangianGrid(
      domain, 50, LagrangianGridConfig{4, 5, 2});
  require(grid.q == 400, "Q was not SCALE * denominator");
  require(!grid.mu.empty() && grid.mu.front() == 0,
          "grid does not contain mu=0");
  require(std::is_sorted(grid.mu.begin(), grid.mu.end()),
          "grid is not deterministic and sorted");
  require(std::adjacent_find(grid.mu.begin(), grid.mu.end()) == grid.mu.end(),
          "grid contains duplicate mu values");
  require(grid.mu.size() <= 5, "grid exceeded requested K");

  require(soci::test_support::plaintextLagrangianScore(3, 0, 50, 100,
                                                        400, 4) == 600,
          "C12 plaintext score is wrong");
  require(soci::test_support::plaintextLagrangianScore(3, 2, 50, 100,
                                                        400, 4) == 1800,
          "C3 plaintext score is wrong");

  const std::vector<PlainLagrangianRow> rows{
      PlainLagrangianRow{10, 1, std::nullopt},
      PlainLagrangianRow{2, std::nullopt, 7},
      PlainLagrangianRow{std::nullopt, 3, 4}};
  verifySoundness(rows, 50, 100, grid);

  const auto root_bounds =
      soci::test_support::plaintextLagrangianLowerBounds(
          rows, {}, 0, 50, 100, grid);
  const std::int64_t old_root_suffix = 1 + 2 + 3;
  require(root_bounds.front() == grid.q * old_root_suffix,
          "mu=0 did not equal the old row-min suffix bound");
  const auto prefix_bounds =
      soci::test_support::plaintextLagrangianLowerBounds(
          rows, {1}, 1, 50, 100, grid);
  require(prefix_bounds.front() == grid.q * (10 + 2 + 3),
          "mu=0 prefix bound differs from old suffix semantics");

  const auto zero_threshold = soci::optimization::buildLagrangianGrid(
      domain, 0, LagrangianGridConfig{4, 9, 10});
  require(zero_threshold.mu == std::vector<std::int64_t>{0},
          "T=0 did not reduce to mu_grid={0}");
  const auto two_point = soci::optimization::buildLagrangianGrid(
      domain, 50, LagrangianGridConfig{4, 2, 2});
  require(two_point.mu.size() == 2,
          "threshold anchors caused grid to exceed requested K");

  // The alpha anchor is 100 here but the small compare domain supports a
  // smaller mu. The builder must truncate/discard the anchor, not fail.
  const soci::secure::NumericDomain anchor_domain{100, 1, 1, 2, 9, 12};
  const auto truncated = soci::optimization::buildLagrangianGrid(
      anchor_domain, 99, LagrangianGridConfig{1, 5, 2});
  const auto truncated_bounds =
      soci::optimization::deriveLagrangianNumericBounds(anchor_domain, 99,
                                                        truncated);
  require(truncated.mu.back() <= truncated_bounds.maximum_supported_mu,
          "grid exceeded the NumericDomain maximum mu");
  require(std::find(truncated.mu.begin(), truncated.mu.end(), 100) ==
              truncated.mu.end(),
          "out-of-range threshold anchor was retained");

  requireStatus(
      [&] {
        (void)soci::optimization::buildLagrangianGrid(
            domain, 50, LagrangianGridConfig{4, 17, 1});
      },
      soci::optimization::Status::invalid_argument,
      "grid larger than the hard limit was accepted");
  requireStatus(
      [&] {
        (void)soci::optimization::buildLagrangianGrid(
            domain, 50, LagrangianGridConfig{0, 3, 1});
      },
      soci::optimization::Status::invalid_argument,
      "zero denominator was accepted");
  requireStatus(
      [&] {
        (void)soci::optimization::buildLagrangianGrid(
            domain, 50,
            LagrangianGridConfig{std::numeric_limits<std::int64_t>::max(),
                                 3, 1});
      },
      soci::optimization::Status::numeric_range_exceeded,
      "overflowing Q was accepted");

  const soci::secure::NumericDomain delta_too_wide{1, 1, 127, 127, 127, 127};
  requireStatus(
      [&] {
        (void)soci::optimization::buildLagrangianGrid(
            delta_too_wide, 0, LagrangianGridConfig{1, 1, 1});
      },
      soci::optimization::Status::numeric_range_exceeded,
      "128-bit score delta was accepted");

  auto narrow_compare = domain;
  narrow_compare.compare_operand_bits = 8;
  requireStatus(
      [&] {
        (void)soci::optimization::buildLagrangianGrid(
            narrow_compare, 50, LagrangianGridConfig{4, 3, 1});
      },
      soci::optimization::Status::numeric_range_exceeded,
      "undersized compare domain was accepted");

  LagrangianGrid missing_zero{400, 4, {1, 2}};
  requireStatus(
      [&] {
        (void)soci::optimization::deriveLagrangianNumericBounds(
            domain, 50, missing_zero);
      },
      soci::optimization::Status::invalid_argument,
      "grid without zero was accepted");

  std::cout << "Lagrangian relaxation configuration tests passed\n";
}
