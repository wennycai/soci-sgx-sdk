#pragma once

#include "soci/optimization.hpp"
#include "soci/secure_ops.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace soci::optimization {

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

// Independent plaintext reference helpers. They do not call SecureOps or the
// encrypted solver.
using PlainLagrangianRow =
    std::array<std::optional<std::int64_t>, 3>;

std::int64_t plaintextLagrangianScore(
    std::int64_t cost, std::size_t method, std::int64_t threshold_scaled,
    std::int64_t scale, std::int64_t q, std::int64_t mu);

std::vector<std::int64_t> plaintextLagrangianLowerBounds(
    const std::vector<PlainLagrangianRow>& rows,
    const std::vector<std::uint8_t>& prefix_methods, std::size_t depth,
    std::int64_t threshold_scaled, std::int64_t scale,
    const LagrangianGrid& grid);

}  // namespace soci::optimization
