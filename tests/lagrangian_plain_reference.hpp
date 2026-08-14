#pragma once

#include "soci/lagrangian_relaxation.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <stdexcept>
#include <vector>

namespace soci::test_support {

using PlainLagrangianRow =
    std::array<std::optional<std::int64_t>, 3>;

inline std::int64_t checkedPlain(__int128 value, const char* message) {
  if (value < std::numeric_limits<std::int64_t>::min() ||
      value > std::numeric_limits<std::int64_t>::max())
    throw std::overflow_error(message);
  return static_cast<std::int64_t>(value);
}

inline std::int64_t plaintextLagrangianScore(
    std::int64_t cost, std::size_t method, std::int64_t threshold,
    std::int64_t scale, std::int64_t q, std::int64_t mu) {
  if (cost < 0 || method >= 3 || scale <= 0 || threshold < 0 ||
      threshold >= scale || q <= 0 || mu < 0)
    throw std::invalid_argument("invalid plaintext Lagrangian score input");
  const __int128 linear = static_cast<__int128>(cost) *
      (method < 2 ? scale - threshold : -threshold);
  return checkedPlain(static_cast<__int128>(q) * cost -
                          static_cast<__int128>(mu) * linear,
                      "plaintext Lagrangian score exceeds int64");
}

inline std::vector<std::int64_t> plaintextLagrangianLowerBounds(
    const std::vector<PlainLagrangianRow>& rows,
    const std::vector<std::uint8_t>& prefix_methods, std::size_t depth,
    std::int64_t threshold, std::int64_t scale,
    const optimization::LagrangianGrid& grid) {
  if (rows.empty() || depth > rows.size() || prefix_methods.size() != depth ||
      grid.mu.empty())
    throw std::invalid_argument("invalid plaintext Lagrangian LB input");
  std::vector<__int128> bounds(grid.mu.size());
  for (std::size_t i = 0; i < rows.size(); ++i) {
    bool available = false;
    for (const auto& cost : rows[i]) available |= cost.has_value();
    if (!available)
      throw std::invalid_argument("plaintext row has no method");
    for (std::size_t k = 0; k < grid.mu.size(); ++k) {
      if (i < depth) {
        const auto method = prefix_methods[i];
        if (method < 1 || method > 3 || !rows[i][method - 1])
          throw std::invalid_argument("invalid plaintext prefix method");
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
    result.push_back(checkedPlain(value, "plaintext Lagrangian LB exceeds int64"));
  return result;
}

}  // namespace soci::test_support
