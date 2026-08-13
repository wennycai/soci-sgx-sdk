#include "soci/predicate_engine.hpp"

#include <cctype>
#include <limits>

namespace soci::secure {
namespace {

bool validIdentifier(const std::string& value) {
  if (value.empty() || value.size() > 128) return false;
  for (const unsigned char character : value)
    if (!std::isalnum(character) && character != '-' && character != '_' &&
        character != '.' && character != ':')
      return false;
  return true;
}

void appendField(std::string& output, const std::string& value) {
  output += std::to_string(value.size());
  output.push_back(':');
  output += value;
  output.push_back('|');
}

}  // namespace

void PredicateEngine::validate(const PredicateContext& context) {
  if (!validIdentifier(context.session_id) ||
      !validIdentifier(context.operation_id) ||
      !validIdentifier(context.node_id))
    throw PredicateError("invalid predicate context identifier");
  if (context.predicate_type != PredicateType::prune_node &&
      context.predicate_type != PredicateType::accept_candidate)
    throw PredicateError("unsupported predicate type");
}

std::string PredicateEngine::replayKey(const PredicateContext& context) {
  std::string key;
  key.reserve(context.session_id.size() + context.operation_id.size() + 32);
  appendField(key, context.session_id);
  appendField(key, context.operation_id);
  return key;
}

bool PredicateEngine::pruneNode(const PredicateContext& context,
                                const EncryptedBit& prune_bit) {
  return evaluateFinalBit(context, PredicateType::prune_node, prune_bit);
}

bool PredicateEngine::acceptCandidate(const PredicateContext& context,
                                      const EncryptedBit& accept_bit) {
  return evaluateFinalBit(context, PredicateType::accept_candidate,
                          accept_bit);
}

bool PredicateEngine::evaluateFinalBit(const PredicateContext& context,
                                       PredicateType expected_type,
                                       const EncryptedBit& final_bit) {
  validate(context);
  if (context.predicate_type != expected_type)
    throw PredicateError("predicate context type does not match operation");
  if (!authorizer_.authorize(context))
    throw PredicateError("predicate evaluation denied");

  // Consume before resolution. A failed/ambiguous reveal must not be retried
  // under the same operation identity.
  {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!consumed_operations_.insert(replayKey(context)).second)
      throw PredicateError("predicate operation replayed");
  }
  return resolver_.revealFinalBit(final_bit);
}

}  // namespace soci::secure
