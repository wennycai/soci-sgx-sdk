#pragma once

#include <gmpxx.h>

#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <vector>

namespace soci::detail {

inline std::vector<std::uint8_t> encodeCanonicalCiphertext(
    std::uint8_t mode, const mpz_class& value) {
  const auto size = (mpz_sizeinbase(value.get_mpz_t(), 2) + 7) / 8;
  std::vector<std::uint8_t> output{'S', 'O', 'C', 'I', 1, 1, mode, 0,
                                   std::uint8_t(size >> 24),
                                   std::uint8_t(size >> 16),
                                   std::uint8_t(size >> 8),
                                   std::uint8_t(size)};
  output.resize(12 + size);
  std::size_t written = 0;
  if (size)
    mpz_export(output.data() + 12, &written, 1, 1, 1, 0,
               value.get_mpz_t());
  if (written != size) throw std::runtime_error("ciphertext export failed");
  return output;
}

inline mpz_class decodeCanonicalCiphertext(const std::uint8_t* data,
                                           std::size_t size,
                                           std::uint8_t mode) {
  if (!data || size < 12 || std::memcmp(data, "SOCI", 4) != 0 ||
      data[4] != 1 || data[5] != 1 || data[6] != mode || data[7] != 0)
    throw std::invalid_argument("invalid ciphertext header/type/mode");
  const std::uint32_t magnitude_size =
      (std::uint32_t(data[8]) << 24) | (std::uint32_t(data[9]) << 16) |
      (std::uint32_t(data[10]) << 8) | data[11];
  if (magnitude_size != size - 12)
    throw std::invalid_argument("invalid ciphertext length");
  if (magnitude_size == 0 || data[12] == 0)
    throw std::invalid_argument("non-canonical ciphertext magnitude");
  mpz_class value;
  if (magnitude_size)
    mpz_import(value.get_mpz_t(), magnitude_size, 1, 1, 1, 0, data + 12);
  return value;
}

}  // namespace soci::detail
