#include "soci/secure_ops.hpp"

#include <string>

namespace soci::secure {

std::vector<Ciphertext> SecureOps::secureMulBatch(
    const std::vector<std::pair<Ciphertext, Ciphertext>>& items) {
  std::vector<Ciphertext> output;
  output.reserve(items.size());
  for (const auto& item : items) output.push_back(secureMul(item.first, item.second));
  return output;
}

std::vector<EncryptedBit> SecureOps::greaterThanBatch(
    const std::vector<std::pair<Ciphertext, Ciphertext>>& items) {
  std::vector<EncryptedBit> output;
  output.reserve(items.size());
  for (const auto& item : items) output.push_back(greaterThan(item.first, item.second));
  return output;
}

Ciphertext SecureOps::sub(const Ciphertext& a, const Ciphertext& b) {
  return add(a, scalarMul(b, -1));
}

EncryptedBit SecureOps::lessThan(const Ciphertext& a, const Ciphertext& b) {
  return greaterThan(b, a);
}

EncryptedBit SecureOps::greaterEqual(const Ciphertext& a,
                                     const Ciphertext& b) {
  return bitNot(lessThan(a, b));
}

EncryptedBit SecureOps::lessEqual(const Ciphertext& a, const Ciphertext& b) {
  return bitNot(greaterThan(a, b));
}

EncryptedBit SecureOps::equal(const Ciphertext& a, const Ciphertext& b) {
  return bitNot(bitOr(greaterThan(a, b), lessThan(a, b)));
}

EncryptedBit SecureOps::bitNot(const EncryptedBit& bit) {
  return encryptedBit(sub(encryptConstant(1), bit.ciphertext()));
}

EncryptedBit SecureOps::bitAnd(const EncryptedBit& a,
                               const EncryptedBit& b) {
  return encryptedBit(secureMul(a.ciphertext(), b.ciphertext()));
}

EncryptedBit SecureOps::bitOr(const EncryptedBit& a,
                              const EncryptedBit& b) {
  const auto product = secureMul(a.ciphertext(), b.ciphertext());
  return encryptedBit(sub(add(a.ciphertext(), b.ciphertext()), product));
}

std::vector<EncryptedBit> SecureOps::bitAndBatch(
    const std::vector<std::pair<EncryptedBit, EncryptedBit>>& items) {
  std::vector<std::pair<Ciphertext, Ciphertext>> operands;
  operands.reserve(items.size());
  for (const auto& item : items)
    operands.emplace_back(item.first.ciphertext(), item.second.ciphertext());
  auto products = secureMulBatch(operands);
  std::vector<EncryptedBit> output;
  output.reserve(products.size());
  for (auto& product : products) output.push_back(encryptedBit(std::move(product)));
  return output;
}

std::vector<EncryptedBit> SecureOps::bitOrBatch(
    const std::vector<std::pair<EncryptedBit, EncryptedBit>>& items) {
  std::vector<std::pair<Ciphertext, Ciphertext>> operands;
  operands.reserve(items.size());
  for (const auto& item : items)
    operands.emplace_back(item.first.ciphertext(), item.second.ciphertext());
  auto products = secureMulBatch(operands);
  std::vector<EncryptedBit> output;
  output.reserve(products.size());
  for (std::size_t i = 0; i < items.size(); ++i)
    output.push_back(encryptedBit(sub(add(items[i].first.ciphertext(),
                                          items[i].second.ciphertext()),
                                      products[i])));
  return output;
}

EncryptedBit SecureOps::bitOrFromProduct(const EncryptedBit& a,
                                         const EncryptedBit& b,
                                         const EncryptedBit& product) {
  return encryptedBit(sub(add(a.ciphertext(), b.ciphertext()),
                          product.ciphertext()));
}

EncryptedBit SecureOps::bitOrExclusive(const EncryptedBit& a,
                                       const EncryptedBit& b) {
  return encryptedBit(add(a.ciphertext(), b.ciphertext()));
}

Ciphertext SecureOps::select(const EncryptedBit& condition,
                             const Ciphertext& true_value,
                             const Ciphertext& false_value) {
  const auto delta = sub(true_value, false_value);
  return add(false_value, secureMul(condition.ciphertext(), delta));
}

Ciphertext SecureOps::min(const Ciphertext& a, const Ciphertext& b) {
  return select(lessThan(a, b), a, b);
}

Ciphertext SecureOps::max(const Ciphertext& a, const Ciphertext& b) {
  return select(greaterThan(a, b), a, b);
}

RuntimeSecureOps::RuntimeSecureOps(Runtime& runtime, NumericDomain domain)
    : runtime_(runtime), domain_(domain) {
  if (runtime_.mode() != SOCI_MODE_OFF) {
    throw Error("RuntimeSecureOps is restricted to OFF/test mode");
  }
}

Ciphertext RuntimeSecureOps::encryptConstant(std::int64_t value) {
  return {runtime_.encrypt(std::to_string(value))};
}

Ciphertext RuntimeSecureOps::add(const Ciphertext& a, const Ciphertext& b) {
  return {runtime_.add(a.bytes, b.bytes)};
}

Ciphertext RuntimeSecureOps::scalarMul(const Ciphertext& a,
                                      std::int64_t scalar) {
  return {runtime_.scalar_mul(a.bytes, std::to_string(scalar))};
}

Ciphertext RuntimeSecureOps::secureMul(const Ciphertext& a,
                                      const Ciphertext& b) {
  return {runtime_.secure_mul(a.bytes, b.bytes)};
}

EncryptedBit RuntimeSecureOps::greaterThan(const Ciphertext& a,
                                           const Ciphertext& b) {
  return encryptedBit({runtime_.secure_compare(a.bytes, b.bytes)});
}

}  // namespace soci::secure
