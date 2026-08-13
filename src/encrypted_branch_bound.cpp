#include "soci/encrypted_optimizer.hpp"

#include <cctype>
#include <functional>
#include <limits>
#include <utility>

namespace soci::optimization {
namespace {

bool validIdentifier(const std::string& value) {
  if (value.empty() || value.size() > 128) return false;
  for (const unsigned char character : value) {
    if (!std::isalnum(character) && character != '-' && character != '_' &&
        character != '.' && character != ':')
      return false;
  }
  return true;
}

[[noreturn]] void invalid(const char* message) {
  throw OptimizationError(Status::invalid_argument, message);
}

struct Prefix {
  secure::Ciphertext total;
  secure::Ciphertext c12;
  secure::Ciphertext c3;
  secure::Ciphertext linear;
};

}  // namespace

EncryptedBranchAndBoundResult EncryptedBranchAndBoundSolver::solve(
    const EncryptedOptimizationRequest& request) {
  const auto& domain = ops_.domain();
  if (request.costs.empty()) invalid("encrypted costs must not be empty");
  if (domain.scale <= 0 || domain.max_rows == 0)
    invalid("SecureOps has an incomplete numeric domain");
  if (request.costs.size() > domain.max_rows)
    invalid("encrypted cost row count exceeds NumericDomain.max_rows");
  if (request.threshold_scaled < 0 ||
      request.threshold_scaled >= domain.scale)
    invalid("threshold_scaled must satisfy 0 <= threshold_scaled < scale");
  if (!validIdentifier(request.session_id)) invalid("invalid session_id");

  for (const auto& row : request.costs) {
    bool available = false;
    for (const auto& method : row.methods) {
      if (!method) continue;
      available = true;
      if (method->bytes.empty()) invalid("available ciphertext is empty");
    }
    if (!available) invalid("every row must have an available method");
  }

  const std::size_t n = request.costs.size();
  const std::int64_t positive = domain.scale - request.threshold_scaled;
  const std::int64_t negative = -request.threshold_scaled;
  const auto zero = ops_.encryptConstant(0);

  std::vector<secure::Ciphertext> row_min_cost;
  std::vector<secure::Ciphertext> row_max_linear;
  row_min_cost.reserve(n);
  row_max_linear.reserve(n);
  for (const auto& row : request.costs) {
    std::optional<secure::Ciphertext> minimum;
    std::optional<secure::Ciphertext> maximum;
    for (std::size_t method = 0; method < row.methods.size(); ++method) {
      if (!row.methods[method]) continue;
      const auto& cost = *row.methods[method];
      minimum = minimum ? ops_.min(*minimum, cost) : cost;
      const auto contribution =
          ops_.scalarMul(cost, method < 2 ? positive : negative);
      maximum = maximum ? ops_.max(*maximum, contribution) : contribution;
    }
    row_min_cost.push_back(std::move(*minimum));
    row_max_linear.push_back(std::move(*maximum));
  }

  std::vector<secure::Ciphertext> min_cost_suffix(n + 1);
  std::vector<secure::Ciphertext> max_linear_suffix(n + 1);
  min_cost_suffix[n] = zero;
  max_linear_suffix[n] = zero;
  for (std::size_t i = n; i-- > 0;) {
    min_cost_suffix[i] = ops_.add(row_min_cost[i], min_cost_suffix[i + 1]);
    max_linear_suffix[i] =
        ops_.add(row_max_linear[i], max_linear_suffix[i + 1]);
  }

  EncryptedBranchAndBoundResult result;
  Prefix incumbent;
  bool has_incumbent = false;
  std::vector<std::uint8_t> current_solution(n);
  std::uint64_t node_sequence = 0;
  std::uint64_t prune_sequence = 0;
  std::uint64_t accept_sequence = 0;

  const auto context = [&](secure::PredicateType type, std::size_t depth,
                           std::uint64_t node, std::string operation) {
    return secure::PredicateContext{request.session_id, std::move(operation),
                                    type, static_cast<std::uint32_t>(depth),
                                    "node-" + std::to_string(node)};
  };

  std::function<void(std::size_t, const Prefix&)> dfs;
  dfs = [&](std::size_t depth, const Prefix& prefix) {
    const std::uint64_t node = ++node_sequence;
    ++result.stats.visited_nodes;
    if (depth == n) {
      ++result.stats.candidate_count;
      const auto operation = "accept-" + std::to_string(++accept_sequence);
      ++result.stats.accept_predicates;
      const bool accept = predicates_.acceptCandidate(
          context(secure::PredicateType::accept_candidate, depth, node,
                  operation),
          {prefix.linear, prefix.c3, prefix.total, prefix.c12, has_incumbent,
           incumbent.total, incumbent.c12});
      if (accept) {
        has_incumbent = true;
        incumbent = prefix;
        result.solution = current_solution;
      }
      return;
    }

    const auto linear_upper =
        ops_.add(prefix.linear, max_linear_suffix[depth]);
    const auto cost_lower = ops_.add(prefix.total, min_cost_suffix[depth]);
    const auto operation = "prune-" + std::to_string(++prune_sequence);
    ++result.stats.prune_predicates;
    if (predicates_.pruneNode(
            context(secure::PredicateType::prune_node, depth, node, operation),
            {linear_upper, cost_lower, has_incumbent, incumbent.total})) {
      ++result.stats.pruned_nodes;
      return;
    }

    for (std::size_t method = 0; method < 3; ++method) {
      if (!request.costs[depth].methods[method]) continue;
      const auto& cost = *request.costs[depth].methods[method];
      Prefix child = prefix;
      child.total = ops_.add(prefix.total, cost);
      if (method < 2) {
        child.c12 = ops_.add(prefix.c12, cost);
      } else {
        child.c3 = ops_.add(prefix.c3, cost);
      }
      child.linear = ops_.add(
          prefix.linear,
          ops_.scalarMul(cost, method < 2 ? positive : negative));
      current_solution[depth] = static_cast<std::uint8_t>(method + 1);
      dfs(depth + 1, child);
    }
  };

  dfs(0, {zero, zero, zero, zero});
  result.feasible = has_incumbent;
  if (has_incumbent) {
    result.total_cost = std::move(incumbent.total);
    result.c12 = std::move(incumbent.c12);
    result.c3 = std::move(incumbent.c3);
    result.linear = std::move(incumbent.linear);
  } else {
    result.solution.clear();
  }
  return result;
}

}  // namespace soci::optimization
