#include "soci/confidential_scalable_optimizer.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <limits>
#include <optional>
#include <random>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace soci::optimization {
namespace {

[[noreturn]] void invalid(const char* message) {
  throw OptimizationError(Status::invalid_argument, message);
}

bool validIdentifier(const std::string& value) {
  if (value.empty() || value.size() > 128) return false;
  for (const unsigned char ch : value)
    if (!std::isalnum(ch) && ch != '-' && ch != '_' && ch != '.' && ch != ':')
      return false;
  return true;
}

bool addBits(std::uint32_t a, std::uint32_t b, std::uint32_t* out) {
  if (a > 127 || b > 127 || a + b > 127) return false;
  *out = a + b;
  return true;
}

// Counted façade.  Keeping composite SecureOps operations here makes the
// profile include their internal ADD/scalarMul/SMUL work too.
class CountedOps {
 public:
  CountedOps(secure::SecureOps& ops, ConfidentialScalableOperationCounts& counts)
      : ops_(ops), counts_(counts) {}

  secure::Ciphertext constant(std::int64_t value) {
    ++counts_.encrypt_constant;
    return ops_.encryptConstant(value);
  }
  secure::Ciphertext add(const secure::Ciphertext& a, const secure::Ciphertext& b) {
    ++counts_.add;
    return ops_.add(a, b);
  }
  secure::Ciphertext scalar(const secure::Ciphertext& a, std::int64_t value) {
    ++counts_.scalar_mul;
    return ops_.scalarMul(a, value);
  }
  secure::Ciphertext sub(const secure::Ciphertext& a, const secure::Ciphertext& b) {
    return add(a, scalar(b, -1));
  }
  secure::Ciphertext mul(const secure::Ciphertext& a, const secure::Ciphertext& b) {
    ++counts_.secure_mul;
    return ops_.secureMul(a, b);
  }
  secure::EncryptedBit greater(const secure::Ciphertext& a,
                                const secure::Ciphertext& b) {
    ++counts_.secure_compare;
    return ops_.greaterThan(a, b);
  }
  secure::EncryptedBit less(const secure::Ciphertext& a,
                             const secure::Ciphertext& b) {
    return greater(b, a);
  }
  secure::EncryptedBit notBit(const secure::EncryptedBit& bit) {
    ++counts_.encrypt_constant;
    ++counts_.scalar_mul;
    ++counts_.add;
    return ops_.bitNot(bit);
  }
  secure::EncryptedBit andBit(const secure::EncryptedBit& a,
                               const secure::EncryptedBit& b) {
    ++counts_.secure_mul;
    return ops_.bitAnd(a, b);
  }
  secure::EncryptedBit orBit(const secure::EncryptedBit& a,
                              const secure::EncryptedBit& b) {
    ++counts_.secure_mul;
    ++counts_.scalar_mul;
    counts_.add += 2;
    return ops_.bitOr(a, b);
  }
  secure::Ciphertext select(const secure::EncryptedBit& condition,
                            const secure::Ciphertext& yes,
                            const secure::Ciphertext& no) {
    ++counts_.secure_select;
    ++counts_.secure_mul;
    ++counts_.scalar_mul;
    counts_.add += 2;
    return ops_.select(condition, yes, no);
  }

 private:
  secure::SecureOps& ops_;
  ConfidentialScalableOperationCounts& counts_;
};

struct Individual {
  std::vector<std::array<secure::Ciphertext, 3>> genes;
  secure::Ciphertext total;
  secure::Ciphertext c12;
  secure::Ciphertext c3;
  secure::Ciphertext linear;
};

class Pega {
 public:
  Pega(secure::SecureOps& ops, ConfidentialScalableOptimizerConfig config,
       const EncryptedOptimizationRequest& request,
       ConfidentialScalableOptimizationStats& stats)
      : raw_(ops), config_(config), request_(request), stats_(stats),
        ops_(ops, stats.run), zero_(ops_.constant(0)), one_(ops_.constant(1)),
        positive_(ops_.constant(ops.domain().scale - request.threshold_scaled)),
        negative_(ops_.constant(-request.threshold_scaled)),
        scale_(ops.domain().scale), maximum_total_(maximumTotal()),
        penalty_(ops_.scalar(ops_.add(maximum_total_, one_),
                             config_.infeasible_penalty)) {}

  ConfidentialScalableOptimizationResult run() {
    std::mt19937_64 random(config_.seed);
    std::vector<Individual> population;
    population.reserve(config_.population);
    population.push_back(repair(cheapest()));
    while (population.size() < config_.population)
      population.push_back(repair(randomIndividual(random)));

    Individual best = population.front();
    for (std::size_t i = 1; i < population.size(); ++i)
      best = choose(better(population[i], best), population[i], best);
    const auto initialization_counts = stats_.run;

    const std::size_t rounds = config_.repair_rounds == 0
                                   ? request_.costs.size() * 3
                                   : config_.repair_rounds;
    stats_.repair_rounds = rounds;
    for (std::size_t generation = 0; generation < config_.generations;
         ++generation) {
      const auto elite = eliteSet(population);
      std::vector<Individual> next = elite;
      next.reserve(config_.population);
      while (next.size() < config_.population) {
        Individual child = tournament(population, random);
        const Individual other = tournament(population, random);
        if (unit(random) < config_.crossover_rate) {
          for (std::size_t row = 0; row < child.genes.size(); ++row)
            if (random() & 1U) child.genes[row] = other.genes[row];
        }
        for (std::size_t row = 0; row < child.genes.size(); ++row) {
          const auto choices = available(row);
          if (unit(random) < config_.mutation_rate && choices.size() > 1) {
            const auto selected = random() % choices.size();
            const auto fallback = choices[(selected + 1) % choices.size()];
            const auto target = oneHot(choices[selected]);
            const auto replacement = oneHot(fallback);
            const auto same = ops_.notBit(ops_.orBit(
                ops_.greater(child.genes[row][choices[selected]], one_),
                ops_.greater(one_, child.genes[row][choices[selected]])));
            for (std::size_t method = 0; method < 3; ++method)
              child.genes[row][method] = ops_.select(
                  same, replacement[method], target[method]);
          }
        }
        next.push_back(repair(evaluate(std::move(child))));
      }
      population = std::move(next);
      for (const auto& value : population)
        best = choose(better(value, best), value, best);
    }
    const auto generation_counts = subtractCounts(stats_.run,
                                                   initialization_counts);

    ConfidentialScalableOptimizationResult result{
        best.genes, best.total, best.c12, best.c3, best.linear, stats_};
    result.stats.per_candidate =
        divideCounts(initialization_counts, config_.population);
    result.stats.per_generation =
        divideCounts(generation_counts, config_.generations);
    const auto population_scale = ceilDivide(256, config_.population);
    result.stats.extrapolated_256x1000 = addCounts(
        multiplyCounts(result.stats.per_candidate, 256ULL),
        multiplyCounts(result.stats.per_generation,
                       saturatedMultiply(1000ULL, population_scale)));
    return result;
  }

 private:
  static double unit(std::mt19937_64& random) {
    return std::generate_canonical<double, 53>(random);
  }

  static std::uint64_t ceilDivide(std::uint64_t value, std::uint64_t divisor) {
    return value / divisor + (value % divisor != 0);
  }
  static ConfidentialScalableOperationCounts divideCounts(
      const ConfidentialScalableOperationCounts& value, std::uint64_t divisor) {
    return {ceilDivide(value.encrypt_constant, divisor), ceilDivide(value.add, divisor),
            ceilDivide(value.scalar_mul, divisor), ceilDivide(value.secure_mul, divisor),
            ceilDivide(value.secure_compare, divisor), ceilDivide(value.secure_select, divisor)};
  }
  static std::uint64_t saturatedMultiply(std::uint64_t value, std::uint64_t factor) {
    return factor && value > std::numeric_limits<std::uint64_t>::max() / factor
               ? std::numeric_limits<std::uint64_t>::max() : value * factor;
  }
  static ConfidentialScalableOperationCounts multiplyCounts(
      const ConfidentialScalableOperationCounts& value, std::uint64_t factor) {
    return {saturatedMultiply(value.encrypt_constant, factor), saturatedMultiply(value.add, factor),
            saturatedMultiply(value.scalar_mul, factor), saturatedMultiply(value.secure_mul, factor),
            saturatedMultiply(value.secure_compare, factor), saturatedMultiply(value.secure_select, factor)};
  }
  static std::uint64_t saturatedAdd(std::uint64_t a, std::uint64_t b) {
    return a > std::numeric_limits<std::uint64_t>::max() - b
               ? std::numeric_limits<std::uint64_t>::max() : a + b;
  }
  static ConfidentialScalableOperationCounts addCounts(
      const ConfidentialScalableOperationCounts& a,
      const ConfidentialScalableOperationCounts& b) {
    return {saturatedAdd(a.encrypt_constant, b.encrypt_constant), saturatedAdd(a.add, b.add),
            saturatedAdd(a.scalar_mul, b.scalar_mul), saturatedAdd(a.secure_mul, b.secure_mul),
            saturatedAdd(a.secure_compare, b.secure_compare), saturatedAdd(a.secure_select, b.secure_select)};
  }
  static ConfidentialScalableOperationCounts subtractCounts(
      const ConfidentialScalableOperationCounts& a,
      const ConfidentialScalableOperationCounts& b) {
    return {a.encrypt_constant - b.encrypt_constant, a.add - b.add,
            a.scalar_mul - b.scalar_mul, a.secure_mul - b.secure_mul,
            a.secure_compare - b.secure_compare,
            a.secure_select - b.secure_select};
  }

  secure::Ciphertext maximumTotal() {
    auto total = zero_;
    for (std::size_t row = 0; row < request_.costs.size(); ++row) {
      const auto choices = available(row);
      auto maximum = *request_.costs[row].methods[choices.front()];
      for (std::size_t index = 1; index < choices.size(); ++index) {
        const auto& candidate = *request_.costs[row].methods[choices[index]];
        maximum = ops_.select(ops_.greater(candidate, maximum), candidate, maximum);
      }
      total = ops_.add(total, maximum);
    }
    return total;
  }

  std::vector<std::size_t> available(std::size_t row) const {
    std::vector<std::size_t> methods;
    for (std::size_t method = 0; method < 3; ++method)
      if (request_.costs[row].methods[method]) methods.push_back(method);
    return methods;
  }

  std::array<secure::Ciphertext, 3> oneHot(std::size_t method) {
    return {method == 0 ? ops_.constant(1) : ops_.constant(0),
            method == 1 ? ops_.constant(1) : ops_.constant(0),
            method == 2 ? ops_.constant(1) : ops_.constant(0)};
  }

  Individual randomIndividual(std::mt19937_64& random) {
    Individual value;
    value.genes.reserve(request_.costs.size());
    for (std::size_t row = 0; row < request_.costs.size(); ++row) {
      const auto choices = available(row);
      value.genes.push_back(oneHot(choices[random() % choices.size()]));
    }
    return evaluate(std::move(value));
  }

  Individual cheapest() {
    Individual value;
    value.genes.reserve(request_.costs.size());
    for (std::size_t row = 0; row < request_.costs.size(); ++row) {
      const auto choices = available(row);
      auto genes = oneHot(choices.front());
      auto chosen = *request_.costs[row].methods[choices.front()];
      for (std::size_t index = 1; index < choices.size(); ++index) {
        const auto method = choices[index];
        const auto is_cheaper = ops_.less(*request_.costs[row].methods[method], chosen);
        chosen = ops_.select(is_cheaper, *request_.costs[row].methods[method], chosen);
        const auto replacement = oneHot(method);
        for (std::size_t bit = 0; bit < 3; ++bit)
          genes[bit] = ops_.select(is_cheaper, replacement[bit], genes[bit]);
      }
      value.genes.push_back(std::move(genes));
    }
    return evaluate(std::move(value));
  }

  Individual evaluate(Individual value) {
    value.total = zero_;
    value.c12 = zero_;
    value.c3 = zero_;
    value.linear = zero_;
    for (std::size_t row = 0; row < request_.costs.size(); ++row) {
      for (std::size_t method = 0; method < 3; ++method) {
        if (!request_.costs[row].methods[method]) continue;
        const auto chosen = ops_.mul(value.genes[row][method],
                                     *request_.costs[row].methods[method]);
        value.total = ops_.add(value.total, chosen);
        if (method < 2)
          value.c12 = ops_.add(value.c12, chosen);
        else
          value.c3 = ops_.add(value.c3, chosen);
        value.linear = ops_.add(
            value.linear, ops_.scalar(chosen, method < 2 ? scale_ - request_.threshold_scaled
                                                          : -request_.threshold_scaled));
      }
    }
    return value;
  }

  secure::EncryptedBit feasible(const Individual& value) {
    const auto linear_nonnegative = ops_.notBit(ops_.less(value.linear, zero_));
    const auto has_method3 = ops_.greater(value.c3, zero_);
    const auto nonzero_total = ops_.greater(value.total, zero_);
    return ops_.andBit(ops_.andBit(linear_nonnegative, has_method3), nonzero_total);
  }

  secure::Ciphertext fitness(const Individual& value) {
    // Plain GA fitness on the common integer scale.  maxTotal and penalty are
    // themselves encrypted cost-derived values.
    const auto negative_linear = ops_.scalar(value.linear, -1);
    const auto violation = ops_.select(ops_.greater(negative_linear, zero_),
                                       negative_linear, zero_);
    const auto missing = ops_.notBit(ops_.greater(value.c3, zero_));
    const auto base = ops_.scalar(value.total, scale_);
    const auto constant = ops_.scalar(penalty_, scale_);
    const auto weighted_violation = ops_.mul(penalty_, violation);
    const auto missing_extent = ops_.add(maximum_total_, one_);
    const auto missing_cost = ops_.mul(
        ops_.mul(penalty_, ops_.scalar(missing_extent, scale_)),
        missing.ciphertext());
    return ops_.add(ops_.add(base, constant),
                    ops_.add(weighted_violation, missing_cost));
  }

  secure::EncryptedBit lexLess(const Individual& a, const Individual& b) {
    auto prefix_equal = ops_.notBit(ops_.greater(zero_, zero_));
    auto lex_less = ops_.greater(zero_, zero_);
    for (std::size_t row = 0; row < a.genes.size(); ++row) {
      auto a_index = ops_.add(a.genes[row][1], ops_.scalar(a.genes[row][2], 2));
      auto b_index = ops_.add(b.genes[row][1], ops_.scalar(b.genes[row][2], 2));
      const auto less = ops_.less(a_index, b_index);
      const auto equal = ops_.notBit(ops_.orBit(ops_.greater(a_index, b_index),
                                                ops_.greater(b_index, a_index)));
      lex_less = ops_.orBit(lex_less, ops_.andBit(prefix_equal, less));
      prefix_equal = ops_.andBit(prefix_equal, equal);
    }
    return lex_less;
  }

  secure::EncryptedBit better(const Individual& a, const Individual& b) {
    const auto feasible_a = feasible(a);
    const auto feasible_b = feasible(b);
    const auto a_only_feasible = ops_.andBit(feasible_a, ops_.notBit(feasible_b));
    const auto total_less = ops_.less(a.total, b.total);
    const auto total_equal = ops_.notBit(ops_.orBit(ops_.greater(a.total, b.total),
                                                    ops_.greater(b.total, a.total)));
    const auto ratio_a = ops_.mul(a.linear, b.total);
    const auto ratio_b = ops_.mul(b.linear, a.total);
    const auto ratio_less = ops_.less(ratio_a, ratio_b);
    const auto ratio_equal = ops_.notBit(ops_.orBit(ops_.greater(ratio_a, ratio_b),
                                                    ops_.greater(ratio_b, ratio_a)));
    const auto tie_lex = ops_.andBit(ratio_equal, lexLess(a, b));
    const auto feasible_better = ops_.orBit(total_less,
        ops_.andBit(total_equal, ops_.orBit(ratio_less, tie_lex)));
    const auto fitness_a = fitness(a);
    const auto fitness_b = fitness(b);
    const auto infeasible_less = ops_.less(fitness_a, fitness_b);
    const auto infeasible_equal = ops_.notBit(ops_.orBit(
        ops_.greater(fitness_a, fitness_b), ops_.greater(fitness_b, fitness_a)));
    const auto infeasible_better = ops_.orBit(infeasible_less,
        ops_.andBit(infeasible_equal, lexLess(a, b)));
    const auto same_class = ops_.andBit(feasible_a, feasible_b);
    const auto both_infeasible = ops_.andBit(ops_.notBit(feasible_a),
                                             ops_.notBit(feasible_b));
    return ops_.orBit(a_only_feasible,
        ops_.orBit(ops_.andBit(same_class, feasible_better),
                   ops_.andBit(both_infeasible, infeasible_better)));
  }

  Individual choose(const secure::EncryptedBit& condition, const Individual& yes,
                    const Individual& no) {
    Individual selected;
    selected.genes.resize(yes.genes.size());
    for (std::size_t row = 0; row < yes.genes.size(); ++row)
      for (std::size_t method = 0; method < 3; ++method)
        selected.genes[row][method] = ops_.select(condition, yes.genes[row][method],
                                                   no.genes[row][method]);
    selected.total = ops_.select(condition, yes.total, no.total);
    selected.c12 = ops_.select(condition, yes.c12, no.c12);
    selected.c3 = ops_.select(condition, yes.c3, no.c3);
    selected.linear = ops_.select(condition, yes.linear, no.linear);
    return selected;
  }

  std::vector<Individual> eliteSet(const std::vector<Individual>& population) {
    std::vector<Individual> elite;
    elite.reserve(config_.elitism);
    elite.push_back(population.front());
    // Public-size insertion networks first establish sorted elite slots, then
    // retain the best E values.  All rank decisions remain encrypted.
    for (std::size_t index = 1; index < population.size(); ++index) {
      Individual carry = population[index];
      for (std::size_t rank = 0; rank < elite.size(); ++rank) {
        const auto wins = better(carry, elite[rank]);
        const auto old = elite[rank];
        elite[rank] = choose(wins, carry, old);
        carry = choose(wins, old, carry);
      }
      if (elite.size() < config_.elitism) elite.push_back(std::move(carry));
    }
    return elite;
  }

  Individual tournament(const std::vector<Individual>& population,
                        std::mt19937_64& random) {
    Individual winner = population[random() % population.size()];
    for (std::size_t turn = 1; turn < config_.tournament_size; ++turn) {
      const auto& challenger = population[random() % population.size()];
      winner = choose(better(challenger, winner), challenger, winner);
    }
    return winner;
  }

  Individual repair(Individual value) {
    const std::size_t rounds = config_.repair_rounds == 0
                                   ? request_.costs.size() * 3
                                   : config_.repair_rounds;
    // Plain repair first installs method3 when it is absent.  This is a
    // distinct fixed scan because that switch normally decreases linear and
    // therefore cannot participate in the positive-delta ratio scan below.
    auto has_method3 = ops_.greater(value.c3, zero_);
    auto have_method3_target = ops_.greater(zero_, zero_);
    auto best_method3_delta = zero_;
    std::vector<secure::Ciphertext> method3_identity;
    method3_identity.reserve(request_.costs.size());
    for (std::size_t row = 0; row < request_.costs.size(); ++row) {
      auto current_cost = zero_;
      for (std::size_t method = 0; method < 3; ++method) {
        if (!request_.costs[row].methods[method]) continue;
        current_cost = ops_.add(
            current_cost,
            ops_.mul(value.genes[row][method],
                     *request_.costs[row].methods[method]));
      }
      const bool available3 = request_.costs[row].methods[2].has_value();
      const auto target_cost = available3 ? *request_.costs[row].methods[2]
                                          : current_cost;
      const auto delta = ops_.sub(target_cost, current_cost);
      const auto cheaper = ops_.less(delta, best_method3_delta);
      const auto public_available = available3 ? one_ : zero_;
      const auto valid = ops_.greater(public_available, zero_);
      const auto replace = ops_.andBit(
          valid, ops_.orBit(ops_.notBit(have_method3_target), cheaper));
      best_method3_delta = ops_.select(replace, delta, best_method3_delta);
      have_method3_target = ops_.orBit(have_method3_target, valid);
      for (auto& identity : method3_identity)
        identity = ops_.select(replace, zero_, identity);
      method3_identity.push_back(ops_.select(replace, one_, zero_));
    }
    const auto add_method3 = ops_.andBit(ops_.notBit(has_method3),
                                         have_method3_target);
    for (std::size_t row = 0; row < request_.costs.size(); ++row) {
      const auto mask = ops_.mul(add_method3.ciphertext(),
                                 method3_identity[row]);
      for (std::size_t method = 0; method < 3; ++method) {
        const auto target = ops_.constant(method == 2);
        value.genes[row][method] = ops_.add(
            value.genes[row][method],
            ops_.mul(mask, ops_.sub(target, value.genes[row][method])));
      }
    }
    value = evaluate(std::move(value));
    for (std::size_t round = 0; round < rounds; ++round) {
      const auto was_feasible = feasible(value);
      auto selected_cost = zero_;
      auto selected_linear = one_;  // Only used after have_selected becomes one.
      auto have_selected = ops_.greater(zero_, zero_);
      std::vector<std::pair<std::size_t, std::size_t>> candidate_positions;
      std::vector<secure::Ciphertext> selected_identity;
      auto method3_count = zero_;
      for (const auto& row : value.genes)
        method3_count = ops_.add(method3_count, row[2]);
      for (std::size_t row = 0; row < request_.costs.size(); ++row) {
        auto current_cost = zero_;
        auto current_linear = zero_;
        for (std::size_t method = 0; method < 3; ++method) {
          if (!request_.costs[row].methods[method]) continue;
          const auto chosen = ops_.mul(value.genes[row][method],
                                       *request_.costs[row].methods[method]);
          current_cost = ops_.add(current_cost, chosen);
          current_linear = ops_.add(current_linear,
              ops_.scalar(chosen, method < 2 ? scale_ - request_.threshold_scaled
                                             : -request_.threshold_scaled));
        }
        for (std::size_t method = 0; method < 3; ++method) {
          if (!request_.costs[row].methods[method]) continue;
          const auto delta_cost = ops_.sub(*request_.costs[row].methods[method], current_cost);
          const auto target_linear = ops_.scalar(*request_.costs[row].methods[method],
              method < 2 ? scale_ - request_.threshold_scaled : -request_.threshold_scaled);
          const auto delta_linear = ops_.sub(target_linear, current_linear);
          auto valid = ops_.greater(delta_linear, zero_);
          // A non-method3 target may not remove the sole selected method3.
          if (method != 2) {
            const auto remaining = ops_.sub(method3_count, value.genes[row][2]);
            valid = ops_.andBit(valid, ops_.greater(remaining, zero_));
          }
          const auto lhs = ops_.mul(delta_cost, selected_linear);
          const auto rhs = ops_.mul(selected_cost, delta_linear);
          const auto smaller = ops_.less(lhs, rhs);
          // Scanning (row, method) in lexical order and retaining equality is
          // the encrypted ratio-equality lexical tie-break.
          const auto replace = ops_.andBit(valid,
              ops_.orBit(ops_.notBit(have_selected), smaller));
          selected_cost = ops_.select(replace, delta_cost, selected_cost);
          selected_linear = ops_.select(replace, delta_linear, selected_linear);
          have_selected = ops_.orBit(have_selected, valid);
          for (auto& identity : selected_identity)
            identity = ops_.select(replace, zero_, identity);
          selected_identity.push_back(ops_.select(replace, one_, zero_));
          candidate_positions.emplace_back(row, method);
        }
      }
      const auto apply = ops_.andBit(ops_.notBit(was_feasible), have_selected);
      // Apply the final selected switch exactly once.  selected_identity is
      // encrypted, so multiply it with the encrypted apply bit instead of
      // resolving or re-wrapping it as an EncryptedBit.
      for (std::size_t index = 0; index < selected_identity.size(); ++index) {
        const auto mask = ops_.mul(apply.ciphertext(), selected_identity[index]);
        const auto [row, method] = candidate_positions[index];
        for (std::size_t target_method = 0; target_method < 3; ++target_method) {
          const auto target = ops_.constant(target_method == method);
          const auto delta = ops_.sub(target, value.genes[row][target_method]);
          value.genes[row][target_method] = ops_.add(
              value.genes[row][target_method], ops_.mul(mask, delta));
        }
      }
      value = evaluate(std::move(value));
    }
    return value;
  }

  secure::SecureOps& raw_;
  ConfidentialScalableOptimizerConfig config_;
  const EncryptedOptimizationRequest& request_;
  ConfidentialScalableOptimizationStats& stats_;
  CountedOps ops_;
  secure::Ciphertext zero_;
  secure::Ciphertext one_;
  secure::Ciphertext positive_;
  secure::Ciphertext negative_;
  std::int64_t scale_;
  secure::Ciphertext maximum_total_;
  secure::Ciphertext penalty_;
};

void validate(const secure::NumericDomain& domain,
              const ConfidentialScalableOptimizerConfig& config,
              const EncryptedOptimizationRequest& request) {
  if (request.costs.empty()) invalid("encrypted costs must not be empty");
  if (domain.scale <= 0 || domain.max_rows == 0 || domain.max_cost_bits == 0 ||
      domain.max_total_bits == 0 || domain.max_linear_bits == 0 ||
      domain.compare_operand_bits == 0)
    invalid("SecureOps has an incomplete numeric domain");
  if (request.costs.size() > domain.max_rows)
    invalid("encrypted cost row count exceeds NumericDomain.max_rows");
  if (request.threshold_scaled < 0 || request.threshold_scaled >= domain.scale)
    invalid("threshold_scaled must satisfy 0 <= threshold_scaled < scale");
  if (!validIdentifier(request.session_id)) invalid("invalid session_id");
  if (config.population < 2 || config.generations == 0 || config.elitism == 0 ||
      config.elitism >= config.population || config.tournament_size == 0 ||
      config.crossover_rate < 0.0 || config.crossover_rate > 1.0 ||
      config.mutation_rate < 0.0 || config.mutation_rate > 1.0 ||
      config.infeasible_penalty <= 0)
    invalid("invalid confidential scalable optimizer configuration");
  if (config.repair_rounds == 0 && request.costs.size() >
          std::numeric_limits<std::size_t>::max() / 3)
    invalid("repair round count overflow");
  for (const auto& row : request.costs) {
    bool any = false;
    for (const auto& cost : row.methods) {
      if (!cost) continue;
      any = true;
      if (cost->bytes.empty()) invalid("available ciphertext is empty");
    }
    if (!any) invalid("every row must have an available method");
  }
  // In addition to declared totals/linear values, PEGA compares cross
  // products and common-scaled fitness.  Reject rather than rely on modular
  // arithmetic whenever an intermediate could leave the signed protocol range.
  std::uint32_t cross_bits{};
  std::uint32_t repair_product_bits{};
  std::uint32_t scaled_total_bits{};
  const auto scale_bits = static_cast<std::uint32_t>(
      64U - __builtin_clzll(static_cast<unsigned long long>(domain.scale)));
  if (!addBits(domain.max_linear_bits, domain.max_total_bits, &cross_bits) ||
      !addBits(domain.max_cost_bits, domain.max_linear_bits, &repair_product_bits) ||
      !addBits(domain.max_total_bits, scale_bits, &scaled_total_bits) ||
      cross_bits > domain.compare_operand_bits ||
      repair_product_bits > domain.compare_operand_bits ||
      scaled_total_bits > domain.compare_operand_bits ||
      domain.max_cost_bits >= 127 || domain.max_total_bits >= 127 ||
      domain.max_linear_bits >= 127 || domain.compare_operand_bits >= 127)
    invalid("NumericDomain cannot bound PEGA intermediates below 2^127");
  const auto multiplier_bits = static_cast<std::uint32_t>(
      64U - __builtin_clzll(static_cast<unsigned long long>(config.infeasible_penalty)));
  std::uint32_t max_total_plus_one_bits{};
  std::uint32_t penalty_bits{};
  std::uint32_t weighted_violation_bits{};
  std::uint32_t missing_extent_bits{};
  std::uint32_t missing_cost_bits{};
  if (!addBits(domain.max_total_bits, 1, &max_total_plus_one_bits) ||
      !addBits(max_total_plus_one_bits, multiplier_bits, &penalty_bits) ||
      !addBits(penalty_bits, domain.max_linear_bits, &weighted_violation_bits) ||
      !addBits(max_total_plus_one_bits, scale_bits, &missing_extent_bits) ||
      !addBits(penalty_bits, missing_extent_bits, &missing_cost_bits) ||
      weighted_violation_bits > domain.compare_operand_bits ||
      missing_cost_bits > domain.compare_operand_bits)
    invalid("NumericDomain cannot bound PEGA fitness below 2^127");
}

}  // namespace

ConfidentialScalableOptimizer::ConfidentialScalableOptimizer(
    secure::SecureOps& ops, ConfidentialScalableOptimizerConfig config)
    : ops_(ops), config_(config) {}

ConfidentialScalableOptimizationResult ConfidentialScalableOptimizer::optimize(
    const EncryptedOptimizationRequest& request) {
  validate(ops_.domain(), config_, request);
  ConfidentialScalableOptimizationStats stats;
  return Pega(ops_, config_, request, stats).run();
}

}  // namespace soci::optimization
