#pragma once

#include "soci/optimization.hpp"
#include "soci/secure_ops.hpp"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace soci::optimization {

inline constexpr std::size_t kMaxLagrangianGridSize = 16;

// rho = lambda * SCALE = mu / denominator, and Q = SCALE * denominator.
struct LagrangianGridConfig {
  std::int64_t denominator{1024};
  std::size_t requested_size{5};
  std::int64_t span_factor{2};
};

struct LagrangianGrid {
  std::int64_t q{};
  std::int64_t denominator{};
  std::vector<std::int64_t> mu;
};

struct LagrangianNumericBounds {
  std::uint32_t score_bits{};
  std::uint32_t score_delta_bits{};
  std::uint32_t bound_bits{};
  std::int64_t maximum_supported_mu{};
};

LagrangianGrid buildLagrangianGrid(
    const secure::NumericDomain& domain, std::int64_t threshold_scaled,
    const LagrangianGridConfig& config = {});

LagrangianNumericBounds deriveLagrangianNumericBounds(
    const secure::NumericDomain& domain, std::int64_t threshold_scaled,
    const LagrangianGrid& grid);

}  // namespace soci::optimization
