#pragma once

#include "soci/optimization.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <limits>
#include <string>

namespace soci::optimization {
namespace detail {
constexpr std::int64_t kFixedScale = 1'000'000;
constexpr std::int64_t kFixedSafe = std::numeric_limits<std::int64_t>::max() / 16;

inline std::string trim_fixed(std::string value) {
  const auto ws = [](unsigned char c) { return std::isspace(c); };
  value.erase(value.begin(), std::find_if_not(value.begin(), value.end(), ws));
  value.erase(std::find_if_not(value.rbegin(), value.rend(), ws).base(), value.end());
  return value;
}

inline std::int64_t parse_fixed_point(const std::string& input, bool threshold) {
  std::string s = trim_fixed(input);
  auto invalid = [](const char* message) -> void {
    throw OptimizationError(Status::invalid_argument, message);
  };
  if (s.empty() || s[0] == '-') invalid("negative or empty decimal");
  if (!s.empty() && s[0] == '+') s.erase(0, 1);
  const auto dot = s.find('.');
  if (dot != std::string::npos && s.find('.', dot + 1) != std::string::npos)
    invalid("invalid decimal");
  std::string whole = dot == std::string::npos ? s : s.substr(0, dot);
  std::string fraction = dot == std::string::npos ? "" : s.substr(dot + 1);
  if (whole.empty()) whole = "0";
  const auto digits = [](const std::string& value) {
    return std::all_of(value.begin(), value.end(),
                       [](unsigned char c) { return std::isdigit(c); });
  };
  if (!digits(whole) || !digits(fraction)) invalid("invalid decimal");
  if (fraction.size() > 6) {
    if (std::any_of(fraction.begin() + 6, fraction.end(),
                    [](char c) { return c != '0'; }))
      invalid("more than six decimal places");
    fraction.resize(6);
  }
  fraction.append(6 - fraction.size(), '0');
  try {
    std::size_t used = 0;
    const auto whole_value = std::stoll(whole, &used);
    const auto fraction_value = std::stoll(fraction);
    if (used != whole.size() ||
        whole_value > (kFixedSafe - fraction_value) / kFixedScale)
      throw OptimizationError(Status::numeric_range_exceeded,
                              "fixed-point value exceeds safe range");
    const auto result = whole_value * kFixedScale + fraction_value;
    if (threshold && result >= kFixedScale)
      invalid("ratio_threshold must satisfy 0 <= T < 1");
    return result;
  } catch (const OptimizationError&) {
    throw;
  } catch (...) {
    throw OptimizationError(Status::numeric_range_exceeded,
                             "fixed-point value exceeds safe range");
  }
}
}  // namespace detail
}  // namespace soci::optimization
