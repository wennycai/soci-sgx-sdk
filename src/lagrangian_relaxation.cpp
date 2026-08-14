#include "soci/lagrangian_relaxation.hpp"

#include <algorithm>
#include <limits>
#include <set>

namespace soci::optimization {
namespace {

using Wide = __int128;
constexpr std::uint32_t kSecureOperandBits = 127;

[[noreturn]] void invalid(const char* message) {
  throw OptimizationError(Status::invalid_argument, message);
}

[[noreturn]] void range(const char* message) {
  throw OptimizationError(Status::numeric_range_exceeded, message);
}

Wide absWide(Wide value) { return value < 0 ? -value : value; }

std::uint32_t ceilLog2(Wide value) {
  if (value <= 0) range("non-positive Lagrangian magnitude bound");
  std::uint32_t bits = 0;
  Wide power = 1;
  while (power < value) {
    if (bits == 127) range("Lagrangian bit calculation overflowed");
    power <<= 1;
    ++bits;
  }
  return bits;
}

std::uint32_t checkedBitSum(std::uint32_t a, std::uint32_t b) {
  if (a > std::numeric_limits<std::uint32_t>::max() - b)
    range("Lagrangian bit calculation overflowed");
  return a + b;
}

Wide coefficientBound(std::int64_t q, std::int64_t mu,
                      std::int64_t alpha, std::int64_t threshold) {
  const Wide c12 = absWide(static_cast<Wide>(q) -
                           static_cast<Wide>(mu) * alpha);
  const Wide c3 = static_cast<Wide>(q) + static_cast<Wide>(mu) * threshold;
  return std::max(c12, c3);
}

struct Bits {
  std::uint32_t score{};
  std::uint32_t delta{};
  std::uint32_t bound{};
};

Bits requiredBits(const secure::NumericDomain& domain, std::int64_t threshold,
                  std::int64_t q, std::int64_t maximum_mu) {
  const Wide g = coefficientBound(q, maximum_mu, domain.scale - threshold,
                                  threshold);
  const auto score = checkedBitSum(domain.max_cost_bits, ceilLog2(g));
  const auto delta = checkedBitSum(score, 1);  // conservative D <= 2G
  const auto bound = checkedBitSum(
      score, ceilLog2(static_cast<Wide>(domain.max_rows)));
  return {score, delta, bound};
}

bool supported(const secure::NumericDomain& domain, std::int64_t threshold,
               std::int64_t q, std::int64_t mu) {
  const auto bits = requiredBits(domain, threshold, q, mu);
  return bits.delta <= kSecureOperandBits &&
         bits.bound <= domain.compare_operand_bits &&
         domain.compare_operand_bits <= kSecureOperandBits;
}

std::int64_t maximumMu(const secure::NumericDomain& domain,
                       std::int64_t threshold, std::int64_t q) {
  if (!supported(domain, threshold, q, 0))
    range("Lagrangian Q exceeds NumericDomain");
  std::int64_t low = 0;
  std::int64_t high = std::numeric_limits<std::int64_t>::max();
  while (low < high) {
    const auto midpoint = low + static_cast<std::int64_t>(
                                    (static_cast<Wide>(high) - low + 1) / 2);
    if (supported(domain, threshold, q, midpoint))
      low = midpoint;
    else
      high = midpoint - 1;
  }
  return low;
}

std::int64_t roundedRatio(std::int64_t a, std::int64_t b,
                          std::int64_t denominator) {
  if (denominator <= 0) invalid("invalid Lagrangian grid ratio");
  const Wide numerator = static_cast<Wide>(a) * b;
  const Wide rounded = (numerator + denominator / 2) / denominator;
  if (rounded > std::numeric_limits<std::int64_t>::max())
    return std::numeric_limits<std::int64_t>::max();
  return static_cast<std::int64_t>(rounded);
}

std::int64_t checkedPlain(Wide value, const char* message) {
  if (value < std::numeric_limits<std::int64_t>::min() ||
      value > std::numeric_limits<std::int64_t>::max())
    range(message);
  return static_cast<std::int64_t>(value);
}

}  // namespace

LagrangianNumericBounds deriveLagrangianNumericBounds(
    const secure::NumericDomain& domain, std::int64_t threshold,
    const LagrangianGrid& grid) {
  if (domain.scale <= 0 || domain.max_rows == 0 ||
      domain.max_cost_bits == 0 || domain.compare_operand_bits == 0)
    invalid("incomplete NumericDomain for Lagrangian relaxation");
  if (threshold < 0 || threshold >= domain.scale)
    invalid("threshold_scaled must satisfy 0 <= threshold_scaled < scale");
  if (grid.q <= 0 || grid.denominator <= 0 || grid.mu.empty())
    invalid("invalid Lagrangian grid");
  if (static_cast<Wide>(domain.scale) * grid.denominator != grid.q)
    invalid("Lagrangian Q must equal SCALE * denominator");
  if (!std::is_sorted(grid.mu.begin(), grid.mu.end()) || grid.mu.front() != 0)
    invalid("Lagrangian mu grid must be sorted and contain zero");
  if (std::adjacent_find(grid.mu.begin(), grid.mu.end()) != grid.mu.end())
    invalid("Lagrangian mu grid must not contain duplicates");
  if (grid.mu.back() < 0) invalid("Lagrangian mu must be non-negative");
  if (domain.compare_operand_bits > kSecureOperandBits)
    range("compare_operand_bits exceeds secure protocol range");

  const auto maximum = maximumMu(domain, threshold, grid.q);
  if (grid.mu.back() > maximum)
    range("Lagrangian mu exceeds NumericDomain");
  const auto bits = requiredBits(domain, threshold, grid.q, grid.mu.back());
  return {bits.score, bits.delta, bits.bound, maximum};
}

LagrangianGrid buildLagrangianGrid(const secure::NumericDomain& domain,
                                   std::int64_t threshold,
                                   const LagrangianGridConfig& config) {
  if (domain.scale <= 0 || config.denominator <= 0 ||
      config.requested_size == 0 || config.span_factor <= 0)
    invalid("invalid Lagrangian grid configuration");
  if (threshold < 0 || threshold >= domain.scale)
    invalid("threshold_scaled must satisfy 0 <= threshold_scaled < scale");
  const Wide q_wide =
      static_cast<Wide>(domain.scale) * config.denominator;
  if (q_wide > std::numeric_limits<std::int64_t>::max())
    range("Lagrangian Q exceeds int64 ScalarMul range");
  const auto q = static_cast<std::int64_t>(q_wide);

  LagrangianGrid grid{q, config.denominator, {0}};
  if (threshold == 0 || config.requested_size == 1) {
    (void)deriveLagrangianNumericBounds(domain, threshold, grid);
    return grid;
  }

  const auto limit = maximumMu(domain, threshold, q);
  const auto alpha_anchor = roundedRatio(
      config.denominator, domain.scale, domain.scale - threshold);
  const auto threshold_anchor = roundedRatio(
      config.denominator, domain.scale, threshold);
  const Wide desired_wide = static_cast<Wide>(config.span_factor) *
                            std::max(alpha_anchor, threshold_anchor);
  const auto desired = desired_wide > std::numeric_limits<std::int64_t>::max()
                           ? std::numeric_limits<std::int64_t>::max()
                           : static_cast<std::int64_t>(desired_wide);
  const auto upper = std::min(limit, desired);

  std::set<std::int64_t> values{0};
  const auto addAnchor = [&](std::int64_t anchor) {
    if (values.size() < config.requested_size && anchor > 0 &&
        anchor <= upper)
      values.insert(anchor);
  };
  addAnchor(alpha_anchor);
  addAnchor(threshold_anchor);
  if (config.requested_size > 1 && upper > 0) {
    const auto intervals = config.requested_size - 1;
    for (std::size_t i = 1; i <= intervals; ++i) {
      const Wide value = (static_cast<Wide>(upper) * i + intervals / 2) /
                         intervals;
      values.insert(static_cast<std::int64_t>(value));
    }
  }

  while (values.size() > config.requested_size) {
    auto it = std::prev(values.end());
    if (*it == alpha_anchor || *it == threshold_anchor) {
      auto candidate = it;
      bool found = false;
      while (candidate != values.begin()) {
        --candidate;
        if (*candidate != 0 && *candidate != alpha_anchor &&
            *candidate != threshold_anchor) {
          found = true;
          break;
        }
      }
      if (!found) break;
      it = candidate;
    }
    values.erase(it);
  }

  grid.mu.assign(values.begin(), values.end());
  (void)deriveLagrangianNumericBounds(domain, threshold, grid);
  return grid;
}

std::int64_t plaintextLagrangianScore(
    std::int64_t cost, std::size_t method, std::int64_t threshold,
    std::int64_t scale, std::int64_t q, std::int64_t mu) {
  if (cost < 0 || method >= 3 || scale <= 0 || threshold < 0 ||
      threshold >= scale || q <= 0 || mu < 0)
    invalid("invalid plaintext Lagrangian score input");
  const Wide linear = static_cast<Wide>(cost) *
      (method < 2 ? scale - threshold : -threshold);
  return checkedPlain(static_cast<Wide>(q) * cost -
                          static_cast<Wide>(mu) * linear,
                      "plaintext Lagrangian score exceeds int64");
}

std::vector<std::int64_t> plaintextLagrangianLowerBounds(
    const std::vector<PlainLagrangianRow>& rows,
    const std::vector<std::uint8_t>& prefix_methods, std::size_t depth,
    std::int64_t threshold, std::int64_t scale,
    const LagrangianGrid& grid) {
  if (rows.empty() || depth > rows.size() || prefix_methods.size() != depth ||
      grid.mu.empty())
    invalid("invalid plaintext Lagrangian lower-bound input");
  std::vector<Wide> bounds(grid.mu.size());
  for (std::size_t i = 0; i < rows.size(); ++i) {
    bool available = false;
    for (const auto& cost : rows[i]) available |= cost.has_value();
    if (!available) invalid("plaintext Lagrangian row has no method");
    for (std::size_t k = 0; k < grid.mu.size(); ++k) {
      if (i < depth) {
        const auto method = prefix_methods[i];
        if (method < 1 || method > 3 || !rows[i][method - 1])
          invalid("invalid plaintext Lagrangian prefix method");
        bounds[k] += plaintextLagrangianScore(
            *rows[i][method - 1], method - 1, threshold, scale, grid.q,
            grid.mu[k]);
      } else {
        std::optional<std::int64_t> minimum;
        for (std::size_t method = 0; method < 3; ++method) {
          if (!rows[i][method]) continue;
          const auto score = plaintextLagrangianScore(
              *rows[i][method], method, threshold, scale, grid.q, grid.mu[k]);
          minimum = minimum ? std::min(*minimum, score) : score;
        }
        bounds[k] += *minimum;
      }
    }
  }
  std::vector<std::int64_t> result;
  result.reserve(bounds.size());
  for (const auto value : bounds)
    result.push_back(
        checkedPlain(value, "plaintext Lagrangian LB exceeds int64"));
  return result;
}

}  // namespace soci::optimization
