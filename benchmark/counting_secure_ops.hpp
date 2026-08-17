#pragma once

#include "soci/secure_ops.hpp"

#include <cstdint>

namespace soci::benchmarking {

struct SecureOpsCounts {
  std::uint64_t encrypt_constant{};
  std::uint64_t add{};
  std::uint64_t scalar_mul{};
  std::uint64_t secure_mul{};
  std::uint64_t secure_compare{};
  std::uint64_t secure_mul_dispatches{};
  std::uint64_t secure_compare_dispatches{};
};

class CountingSecureOps final : public secure::SecureOps {
 public:
  explicit CountingSecureOps(secure::SecureOps& delegate)
      : delegate_(delegate) {}

  secure::Ciphertext encryptConstant(std::int64_t value) override {
    ++counts_.encrypt_constant;
    return delegate_.encryptConstant(value);
  }
  secure::Ciphertext add(const secure::Ciphertext& a,
                         const secure::Ciphertext& b) override {
    ++counts_.add;
    return delegate_.add(a, b);
  }
  secure::Ciphertext scalarMul(const secure::Ciphertext& a,
                               std::int64_t scalar) override {
    ++counts_.scalar_mul;
    return delegate_.scalarMul(a, scalar);
  }
  secure::Ciphertext secureMul(const secure::Ciphertext& a,
                               const secure::Ciphertext& b) override {
    ++counts_.secure_mul;
    ++counts_.secure_mul_dispatches;
    return delegate_.secureMul(a, b);
  }
  std::vector<secure::Ciphertext> secureMulBatch(
      const std::vector<std::pair<secure::Ciphertext,secure::Ciphertext>>& items) override {
    counts_.secure_mul += items.size();
    ++counts_.secure_mul_dispatches;
    return delegate_.secureMulBatch(items);
  }
  secure::EncryptedBit greaterThan(const secure::Ciphertext& a,
                                   const secure::Ciphertext& b) override {
    ++counts_.secure_compare;
    ++counts_.secure_compare_dispatches;
    return delegate_.greaterThan(a, b);
  }
  std::vector<secure::EncryptedBit> greaterThanBatch(
      const std::vector<std::pair<secure::Ciphertext,secure::Ciphertext>>& items) override {
    counts_.secure_compare += items.size();
    ++counts_.secure_compare_dispatches;
    return delegate_.greaterThanBatch(items);
  }
  const secure::NumericDomain& domain() const noexcept override {
    return delegate_.domain();
  }

  const SecureOpsCounts& counts() const noexcept { return counts_; }

 private:
  secure::SecureOps& delegate_;
  SecureOpsCounts counts_;
};

}  // namespace soci::benchmarking
