#include "soci/predicate_engine.hpp"

#include <filesystem>
#include <iostream>
#include <stdexcept>

namespace {

class TestAuthorizer final : public soci::secure::PredicateAuthorizer {
 public:
  bool allow{true};
  std::size_t calls{};
  bool authorize(const soci::secure::PredicateContext&) override {
    ++calls;
    return allow;
  }
};

class RuntimeBitResolver final : public soci::secure::PredicateBitResolver {
 public:
  explicit RuntimeBitResolver(soci::Runtime& runtime) : runtime_(runtime) {}
  std::size_t calls{};

 private:
  bool revealFinalBit(const soci::secure::PredicateContext&,
                      const soci::secure::EncryptedBit& bit) override {
    ++calls;
    const auto plaintext = runtime_.decrypt(bit.ciphertext().bytes);
    if (plaintext == "0") return false;
    if (plaintext == "1") return true;
    throw soci::secure::PredicateError("encrypted predicate is not a bit");
  }
  soci::Runtime& runtime_;
};

void require(bool condition, const char* message) {
  if (!condition) throw std::runtime_error(message);
}

soci::secure::PredicateContext context(
    std::string operation, soci::secure::PredicateType type) {
  return {"session-1", std::move(operation), type, 7, "node-42"};
}

template <typename Operation>
void requireRejected(Operation operation, const char* message) {
  try {
    operation();
  } catch (const soci::secure::PredicateError&) {
    return;
  }
  throw std::runtime_error(message);
}

}  // namespace

int main() {
  const auto directory = std::filesystem::temp_directory_path() /
                         "soci-predicate-engine-test";
  std::filesystem::remove_all(directory);
  soci::Runtime runtime(directory.string());
  runtime.create_key("predicate-engine");
  soci::secure::RuntimeSecureOps ops(runtime);
  TestAuthorizer authorizer;
  RuntimeBitResolver resolver(runtime);
  soci::secure::PredicateEngine engine(ops, authorizer, resolver);
  const auto number = [&](std::int64_t value) {
    return ops.encryptConstant(value);
  };
  const auto prune = [&](std::string id, std::int64_t linear,
                         std::int64_t lower, bool has_best,
                         std::int64_t best) {
    const auto before = resolver.calls;
    const bool result = engine.pruneNode(
        context(std::move(id), soci::secure::PredicateType::prune_node),
        {number(linear), number(lower), has_best, number(best)});
    require(resolver.calls == before + 1, "PRUNE revealed an intermediate bit");
    return result;
  };
  const auto accept = [&](std::string id, std::int64_t linear,
                          std::int64_t c3, std::int64_t cost,
                          std::int64_t c12, bool has_best,
                          std::int64_t best_cost, std::int64_t best_c12) {
    const auto before = resolver.calls;
    const bool result = engine.acceptCandidate(
        context(std::move(id), soci::secure::PredicateType::accept_candidate),
        {number(linear), number(c3), number(cost), number(c12), has_best,
         number(best_cost), number(best_c12)});
    require(resolver.calls == before + 1, "ACCEPT revealed an intermediate bit");
    return result;
  };

  require(prune("ratio-negative", -1, 5, false, 0),
          "negative linear_upper did not prune");
  require(!prune("ratio-zero", 0, 5, false, 0),
          "zero linear_upper pruned");
  require(prune("cost-greater", 1, 11, true, 10),
          "larger lower bound did not prune");
  require(!prune("cost-equal", 1, 10, true, 10),
          "equal lower bound pruned");
  require(!prune("no-incumbent", 1, 99, false, 1),
          "cost pruned without incumbent");

  const auto multi_before = resolver.calls;
  require(engine.pruneNode(
              context("multi-cost-prune",
                      soci::secure::PredicateType::prune_node),
              {number(0),
               std::vector<soci::secure::Ciphertext>{number(8), number(11),
                                                     number(10)},
               true, number(10)}),
          "multiple lower bounds were not ORed");
  require(resolver.calls == multi_before + 1,
          "multiple lower bounds revealed more than one PRUNE bit");
  require(!engine.pruneNode(
              context("multi-cost-equal",
                      soci::secure::PredicateType::prune_node),
              {number(0),
               std::vector<soci::secure::Ciphertext>{number(9), number(10)},
               true, number(10)}),
          "equal multiple lower bound pruned");
  require(!engine.pruneNode(
              context("empty-cost-no-incumbent",
                      soci::secure::PredicateType::prune_node),
              {number(0),
               std::vector<soci::secure::Ciphertext>{
                   soci::secure::Ciphertext{{1, 2, 3}}},
               false, {}}),
          "objective bounds were evaluated without an incumbent");
  requireRejected(
      [&] {
        engine.pruneNode(
            context("empty-cost-with-incumbent",
                    soci::secure::PredicateType::prune_node),
            {number(0), std::vector<soci::secure::Ciphertext>{}, true,
             number(10)});
      },
      "missing objective bounds were accepted with an incumbent");

  require(accept("first-feasible", 0, 1, 10, 6, false, 0, 0),
          "first feasible candidate rejected");
  require(!accept("zero-c3", 0, 0, 10, 6, false, 0, 0),
          "candidate with c3=0 accepted");
  require(accept("lower-cost", 0, 1, 9, 8, true, 10, 6),
          "lower-cost candidate rejected");
  require(accept("equal-cost-better-c12", 0, 1, 10, 5, true, 10, 6),
          "equal-cost better-c12 candidate rejected");
  require(!accept("equal-candidate", 0, 1, 10, 6, true, 10, 6),
          "equal candidate accepted");
  require(!accept("higher-cost", 0, 1, 11, 5, true, 10, 6),
          "higher-cost candidate accepted");

  authorizer.allow = false;
  const auto calls_before_denial = resolver.calls;
  requireRejected(
      [&] {
        engine.pruneNode(context("denied",
                                 soci::secure::PredicateType::prune_node),
                         {number(-1), number(0), false, {}});
      },
      "denied predicate was evaluated");
  require(resolver.calls == calls_before_denial,
          "resolver ran before authorization");
  authorizer.allow = true;

  const auto replay = context("replay", soci::secure::PredicateType::prune_node);
  soci::secure::PruneInputs replay_inputs{number(-1), number(0), false, {}};
  require(engine.pruneNode(replay, replay_inputs), "first replay operation failed");
  requireRejected([&] { engine.pruneNode(replay, replay_inputs); },
                  "predicate replay was accepted");

  auto duplicate = replay;
  duplicate.depth++;
  duplicate.node_id = "different-node";
  requireRejected([&] { engine.pruneNode(duplicate, replay_inputs); },
                  "operation identity was reusable with altered context");

  auto invalid = context("invalid", soci::secure::PredicateType::prune_node);
  invalid.session_id.clear();
  requireRejected([&] { engine.pruneNode(invalid, replay_inputs); },
                  "empty session was accepted");
  invalid = context("invalid-type", static_cast<soci::secure::PredicateType>(9));
  requireRejected([&] { engine.pruneNode(invalid, replay_inputs); },
                  "unknown predicate type was accepted");

  auto mismatch =
      context("mismatch", soci::secure::PredicateType::accept_candidate);
  requireRejected([&] { engine.pruneNode(mismatch, replay_inputs); },
                  "predicate operation/type mismatch was accepted");

  std::filesystem::remove_all(directory);
  std::cout << "PredicateEngine authorization tests passed\n";
}
