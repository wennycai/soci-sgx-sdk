#pragma once

#include "soci/secure_ops.hpp"

#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_set>

namespace soci::secure {

enum class PredicateType : std::uint8_t {
  prune_node = 1,
  accept_candidate = 2,
};

struct PredicateContext {
  std::string session_id;
  std::string operation_id;
  PredicateType predicate_type{};
  std::uint32_t depth{};
  std::string node_id;
};

class PredicateAuthorizer {
 public:
  virtual ~PredicateAuthorizer() = default;
  virtual bool authorize(const PredicateContext& context) = 0;
};

// Deliberately narrower than a decryptor: implementations may reveal only an
// encrypted bit and must never expose arbitrary plaintext through this API.
class PredicateBitResolver {
 public:
  virtual ~PredicateBitResolver() = default;

 private:
  virtual bool revealFinalBit(const EncryptedBit& bit) = 0;
  friend class PredicateEngine;
};

class PredicateError : public Error {
 public:
  using Error::Error;
};

class PredicateEngine final {
 public:
  PredicateEngine(PredicateAuthorizer& authorizer,
                  PredicateBitResolver& resolver)
      : authorizer_(authorizer), resolver_(resolver) {}

  bool pruneNode(const PredicateContext& context,
                 const EncryptedBit& prune_bit);
  bool acceptCandidate(const PredicateContext& context,
                       const EncryptedBit& accept_bit);

 private:
  bool evaluateFinalBit(const PredicateContext& context,
                        PredicateType expected_type,
                        const EncryptedBit& final_bit);
  static void validate(const PredicateContext& context);
  static std::string replayKey(const PredicateContext& context);

  PredicateAuthorizer& authorizer_;
  PredicateBitResolver& resolver_;
  std::mutex mutex_;
  std::unordered_set<std::string> consumed_operations_;
};

}  // namespace soci::secure
