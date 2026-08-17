#pragma once

#include "soci/soci.hpp"

#include <cstddef>
#include <cstdint>
#include <utility>
#include <vector>

namespace soci::secure {

using Bytes = std::vector<std::uint8_t>;

struct Ciphertext {
  Bytes bytes;
};

class EncryptedBit {
 public:
  const Ciphertext& ciphertext() const noexcept { return value_; }

 private:
  explicit EncryptedBit(Ciphertext value) : value_(std::move(value)) {}

  Ciphertext value_;
  friend class SecureOps;
};

struct NumericDomain {
  // Bit fields bound plaintext magnitudes: a value of b means |x| < 2^b.
  // ThresholdSecureOps additionally requires every possible SMUL operand to
  // satisfy |x| < 2^127.
  std::int64_t scale{1'000'000};
  std::size_t max_rows{};
  std::uint32_t max_cost_bits{};
  std::uint32_t max_total_bits{};
  std::uint32_t max_linear_bits{};
  std::uint32_t compare_operand_bits{};
};

class SecureOps {
 public:
  virtual ~SecureOps() = default;

  virtual Ciphertext encryptConstant(std::int64_t value) = 0;
  virtual Ciphertext add(const Ciphertext& a, const Ciphertext& b) = 0;
  virtual Ciphertext scalarMul(const Ciphertext& a, std::int64_t scalar) = 0;
  virtual Ciphertext secureMul(const Ciphertext& a, const Ciphertext& b) = 0;
  virtual std::vector<Ciphertext> secureMulBatch(
      const std::vector<std::pair<Ciphertext, Ciphertext>>& items);

  // Returns Enc(a > b). This direction is part of the public contract.
  virtual EncryptedBit greaterThan(const Ciphertext& a,
                                   const Ciphertext& b) = 0;
  virtual std::vector<EncryptedBit> greaterThanBatch(
      const std::vector<std::pair<Ciphertext, Ciphertext>>& items);

  Ciphertext sub(const Ciphertext& a, const Ciphertext& b);
  EncryptedBit lessThan(const Ciphertext& a, const Ciphertext& b);
  EncryptedBit greaterEqual(const Ciphertext& a, const Ciphertext& b);
  EncryptedBit lessEqual(const Ciphertext& a, const Ciphertext& b);
  EncryptedBit equal(const Ciphertext& a, const Ciphertext& b);
  EncryptedBit bitNot(const EncryptedBit& bit);
  EncryptedBit bitAnd(const EncryptedBit& a, const EncryptedBit& b);
  EncryptedBit bitOr(const EncryptedBit& a, const EncryptedBit& b);
  std::vector<EncryptedBit> bitAndBatch(
      const std::vector<std::pair<EncryptedBit, EncryptedBit>>& items);
  std::vector<EncryptedBit> bitOrBatch(
      const std::vector<std::pair<EncryptedBit, EncryptedBit>>& items);
  EncryptedBit bitOrFromProduct(const EncryptedBit& a, const EncryptedBit& b,
                                const EncryptedBit& product);
  // Adds bits whose conjunction is known by the caller to be zero.  This is
  // intentionally distinct from bitOr: misuse on non-exclusive inputs would
  // not produce a bit.
  EncryptedBit bitOrExclusive(const EncryptedBit& a, const EncryptedBit& b);
  Ciphertext select(const EncryptedBit& condition,
                    const Ciphertext& true_value,
                    const Ciphertext& false_value);
  Ciphertext min(const Ciphertext& a, const Ciphertext& b);
  Ciphertext max(const Ciphertext& a, const Ciphertext& b);

  virtual const NumericDomain& domain() const noexcept = 0;

 protected:
  static EncryptedBit encryptedBit(Ciphertext value) {
    return EncryptedBit(std::move(value));
  }
};

// OFF/test backend. Production SIM/HW code must use ThresholdSecureOps.
class RuntimeSecureOps final : public SecureOps {
 public:
  explicit RuntimeSecureOps(Runtime& runtime, NumericDomain domain = {});

  Ciphertext encryptConstant(std::int64_t value) override;
  Ciphertext add(const Ciphertext& a, const Ciphertext& b) override;
  Ciphertext scalarMul(const Ciphertext& a, std::int64_t scalar) override;
  Ciphertext secureMul(const Ciphertext& a, const Ciphertext& b) override;
  EncryptedBit greaterThan(const Ciphertext& a,
                           const Ciphertext& b) override;
  const NumericDomain& domain() const noexcept override { return domain_; }

 private:
  Runtime& runtime_;
  NumericDomain domain_;
};

}  // namespace soci::secure
