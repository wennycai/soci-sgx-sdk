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
                                const PruneInputs& inputs) {
  const auto zero = ops_.encryptConstant(0);
  auto final_bit = ops_.lessThan(inputs.linear_upper, zero);
  if (inputs.has_incumbent) {
    if (inputs.incumbent_cost.bytes.empty())
      throw PredicateError("missing incumbent cost");
    if (inputs.cost_lowers.empty())
      throw PredicateError("missing cost lower bounds");
    auto cost_prune =
        ops_.greaterThan(inputs.cost_lowers.front(), inputs.incumbent_cost);
    for (std::size_t i = 1; i < inputs.cost_lowers.size(); ++i)
      cost_prune = ops_.bitOr(
          cost_prune,
          ops_.greaterThan(inputs.cost_lowers[i], inputs.incumbent_cost));
    final_bit = ops_.bitOr(final_bit, cost_prune);
  }
  return evaluateFinalBit(context, PredicateType::prune_node, final_bit);
}

bool PredicateEngine::acceptCandidate(const PredicateContext& context,
                                      const AcceptInputs& inputs) {
  const auto zero = ops_.encryptConstant(0);
  const auto feasible = ops_.bitAnd(ops_.greaterEqual(inputs.linear, zero),
                                    ops_.greaterThan(inputs.c3, zero));
  auto final_bit = feasible;
  if (inputs.has_incumbent) {
    if (inputs.incumbent_cost.bytes.empty() ||
        inputs.incumbent_c12.bytes.empty())
      throw PredicateError("missing incumbent values");
    const auto cost_lt = ops_.lessThan(inputs.cost, inputs.incumbent_cost);
    const auto cost_eq = ops_.equal(inputs.cost, inputs.incumbent_cost);
    const auto c12_lt = ops_.lessThan(inputs.c12, inputs.incumbent_c12);
    const auto better = ops_.bitOr(cost_lt, ops_.bitAnd(cost_eq, c12_lt));
    final_bit = ops_.bitAnd(feasible, better);
  }
  return evaluateFinalBit(context, PredicateType::accept_candidate, final_bit);
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
  return resolver_.revealFinalBit(context, final_bit);
}

}  // namespace soci::secure
