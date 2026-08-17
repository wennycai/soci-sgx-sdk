#pragma once

#include "soci/secure_ops.hpp"
#include "soci/predicate_engine.hpp"
#include "soci/threshold_limits.h"

#include <gmpxx.h>
#include <cstdint>
#include <memory>
#include <string>

namespace soci::protocol {

enum class ThresholdMode : std::uint8_t { sim = 1, hw = 2 };

struct ProtocolMetrics {
  double cp_enclave_microseconds{};
  double network_microseconds{};
  double host_encrypt_microseconds{};
  double host_scalar_powm_microseconds{};
  double csp_enclave_microseconds{};
  std::uint64_t host_encrypt_calls{};
  std::uint64_t host_scalar_powm_calls{};
  std::uint64_t logical_items{};
  std::uint64_t cp_ecalls{};
  std::uint64_t csp_requests{};
  std::uint64_t csp_ecalls{};
  std::uint64_t scmp_logical_items{};
  std::uint64_t scmp_dispatches{};
  std::uint64_t smul_logical_items{};
  std::uint64_t smul_dispatches{};
  std::uint64_t predicate_reveals{};
};

class ThresholdProtocolClient {
 public:
  ThresholdProtocolClient(std::string enclave_path, std::string key_directory,
                          std::string csp_host, int csp_port,
                          ThresholdMode mode);
  ~ThresholdProtocolClient();
  ThresholdProtocolClient(const ThresholdProtocolClient&) = delete;
  ThresholdProtocolClient& operator=(const ThresholdProtocolClient&) = delete;

  mpz_class encrypt(const mpz_class& plaintext);
  mpz_class add(const mpz_class& a, const mpz_class& b) const;
  mpz_class scalarMultiply(const mpz_class& value,
                           const mpz_class& scalar) const;
  mpz_class secureMultiply(const mpz_class& a, const mpz_class& b,
                           ProtocolMetrics* metrics = nullptr);
  std::vector<mpz_class> secureMultiplyBatch(
      const std::vector<std::pair<mpz_class, mpz_class>>& items,
      ProtocolMetrics* metrics = nullptr);
  // Returns Enc(a > b).
  mpz_class greaterThan(const mpz_class& a, const mpz_class& b,
                        ProtocolMetrics* metrics = nullptr);
  std::vector<mpz_class> greaterThanBatch(
      const std::vector<std::pair<mpz_class, mpz_class>>& items,
      ProtocolMetrics* metrics = nullptr);

  // Management/benchmark API only; it is deliberately absent from SecureOps.
  mpz_class decryptForTesting(const mpz_class& ciphertext,
                              ProtocolMetrics* metrics = nullptr);
  void requestServerShutdown();
  const mpz_class& modulus() const noexcept;
  ThresholdMode mode() const noexcept;
  const ProtocolMetrics& metrics() const noexcept;

 private:
  bool revealFinalPredicate(const secure::PredicateContext& context,
                            const mpz_class& encrypted_bit,
                            ProtocolMetrics* metrics = nullptr);
  class Impl;
  std::unique_ptr<Impl> impl_;
  friend class ThresholdPredicateBitResolver;
};

class ThresholdSecureOps final : public secure::SecureOps {
 public:
  ThresholdSecureOps(ThresholdProtocolClient& protocol,
                     secure::NumericDomain domain);

  secure::Ciphertext encryptConstant(std::int64_t value) override;
  secure::Ciphertext add(const secure::Ciphertext& a,
                         const secure::Ciphertext& b) override;
  secure::Ciphertext scalarMul(const secure::Ciphertext& a,
                               std::int64_t scalar) override;
  secure::Ciphertext secureMul(const secure::Ciphertext& a,
                               const secure::Ciphertext& b) override;
  std::vector<secure::Ciphertext> secureMulBatch(
      const std::vector<std::pair<secure::Ciphertext, secure::Ciphertext>>& items) override;
  secure::EncryptedBit greaterThan(const secure::Ciphertext& a,
                                   const secure::Ciphertext& b) override;
  std::vector<secure::EncryptedBit> greaterThanBatch(
      const std::vector<std::pair<secure::Ciphertext, secure::Ciphertext>>& items) override;
  const secure::NumericDomain& domain() const noexcept override {
    return domain_;
  }

 private:
  ThresholdProtocolClient& protocol_;
  secure::NumericDomain domain_;
};

class ThresholdPredicateBitResolver final
    : public secure::PredicateBitResolver {
 public:
  explicit ThresholdPredicateBitResolver(ThresholdProtocolClient& protocol)
      : protocol_(protocol) {}
 private:
  bool revealFinalBit(const secure::PredicateContext& context,
                      const secure::EncryptedBit& bit) override;
  ThresholdProtocolClient& protocol_;
};

int provisionThresholdKeys(const std::string& enclave_path,
                           const std::string& directory, unsigned bits,
                           ThresholdMode mode);
int runThresholdCsp(const std::string& enclave_path,
                    const std::string& key_directory, int port,
                    ThresholdMode mode);
const char* thresholdModeName(ThresholdMode mode) noexcept;

}  // namespace soci::protocol
