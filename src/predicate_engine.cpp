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
  std::vector<std::pair<Ciphertext, Ciphertext>> comparisons;
  comparisons.emplace_back(zero, inputs.linear_upper); // linear_upper < 0
  if (inputs.has_incumbent) {
    if (inputs.incumbent_cost.bytes.empty())
      throw PredicateError("missing incumbent cost");
    if (inputs.cost_lowers.empty())
      throw PredicateError("missing cost lower bounds");
    for (const auto& lower : inputs.cost_lowers)
      comparisons.emplace_back(lower, inputs.incumbent_cost);
  }
  auto bits = ops_.greaterThanBatch(comparisons);
  auto final_bit = std::move(bits.front());
  if (inputs.has_incumbent) {
    std::vector<EncryptedBit> layer;
    layer.reserve(bits.size()-1);
    for(std::size_t i=1;i<bits.size();++i) layer.push_back(std::move(bits[i]));
    while(layer.size()>1){
      std::vector<std::pair<EncryptedBit,EncryptedBit>> pairs;
      for(std::size_t i=0;i+1<layer.size();i+=2) pairs.emplace_back(layer[i],layer[i+1]);
      auto next=ops_.bitOrBatch(pairs);
      if(layer.size()&1) next.push_back(std::move(layer.back()));
      layer=std::move(next);
    }
    auto cost_prune = std::move(layer.front());
    final_bit = ops_.bitOr(final_bit, cost_prune);
  }
  return evaluateFinalBit(context, PredicateType::prune_node, final_bit);
}

bool PredicateEngine::acceptCandidate(const PredicateContext& context,
                                      const AcceptInputs& inputs) {
  const auto zero = ops_.encryptConstant(0);
  std::vector<std::pair<Ciphertext, Ciphertext>> comparisons{
      {zero, inputs.linear}, {inputs.c3, zero}};
  if (inputs.has_incumbent) {
    if (inputs.incumbent_cost.bytes.empty() ||
        inputs.incumbent_c12.bytes.empty())
      throw PredicateError("missing incumbent values");
    comparisons.emplace_back(inputs.incumbent_cost, inputs.cost); // cost < incumbent
    comparisons.emplace_back(inputs.cost, inputs.incumbent_cost);
    comparisons.emplace_back(inputs.incumbent_c12, inputs.c12); // c12 < incumbent
  }
  auto compared = ops_.greaterThanBatch(comparisons);
  const auto linear_ge = ops_.bitNot(compared[0]);
  if (!inputs.has_incumbent) {
    const auto feasible = ops_.bitAnd(linear_ge, compared[1]);
    return evaluateFinalBit(context, PredicateType::accept_candidate, feasible);
  }
  // Both products are in the same dependency layer.  Their inputs are only
  // comparison results, so scheduling them together is non-speculative.
  auto first_products=ops_.bitAndBatch({{linear_ge,compared[1]},
                                       {compared[2],compared[3]}});
  auto feasible=std::move(first_products[0]);
  auto cost_neq=ops_.bitOrFromProduct(compared[2],compared[3],first_products[1]);
  auto cost_eq=ops_.bitNot(cost_neq);
  const auto equal_and_c12=ops_.bitAnd(cost_eq,compared[4]);
  const auto better=ops_.bitOr(compared[2],equal_and_c12);
  const auto final_bit=ops_.bitAnd(feasible,better);
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
