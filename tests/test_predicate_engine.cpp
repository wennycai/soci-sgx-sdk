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
  bool revealFinalBit(const soci::secure::EncryptedBit& bit) override {
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
  soci::secure::PredicateEngine engine(authorizer, resolver);
  const auto yes = ops.greaterThan(ops.encryptConstant(5),
                                   ops.encryptConstant(3));
  const auto no = ops.greaterThan(ops.encryptConstant(3),
                                  ops.encryptConstant(5));

  require(engine.pruneNode(context("prune-1",
                                   soci::secure::PredicateType::prune_node),
                           yes),
          "PRUNE_NODE true failed");
  require(!engine.acceptCandidate(
              context("accept-1",
                      soci::secure::PredicateType::accept_candidate),
              no),
          "ACCEPT_CANDIDATE false failed");

  authorizer.allow = false;
  const auto calls_before_denial = resolver.calls;
  requireRejected(
      [&] {
        engine.pruneNode(context("denied",
                                 soci::secure::PredicateType::prune_node),
                         yes);
      },
      "denied predicate was evaluated");
  require(resolver.calls == calls_before_denial,
          "resolver ran before authorization");
  authorizer.allow = true;

  const auto replay = context("replay", soci::secure::PredicateType::prune_node);
  require(engine.pruneNode(replay, yes), "first replay operation failed");
  requireRejected([&] { engine.pruneNode(replay, yes); },
                  "predicate replay was accepted");

  auto duplicate = replay;
  duplicate.depth++;
  duplicate.node_id = "different-node";
  requireRejected([&] { engine.pruneNode(duplicate, yes); },
                  "operation identity was reusable with altered context");

  auto invalid = context("invalid", soci::secure::PredicateType::prune_node);
  invalid.session_id.clear();
  requireRejected([&] { engine.pruneNode(invalid, yes); },
                  "empty session was accepted");
  invalid = context("invalid-type", static_cast<soci::secure::PredicateType>(9));
  requireRejected([&] { engine.pruneNode(invalid, yes); },
                  "unknown predicate type was accepted");

  auto mismatch =
      context("mismatch", soci::secure::PredicateType::accept_candidate);
  requireRejected([&] { engine.pruneNode(mismatch, yes); },
                  "predicate operation/type mismatch was accepted");

  std::filesystem::remove_all(directory);
  std::cout << "PredicateEngine authorization tests passed\n";
}
