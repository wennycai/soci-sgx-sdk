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
    ++counts_.secure_mul_dispatches;
    return ops_.secureMul(a, b);
  }
  std::vector<secure::Ciphertext> mulBatch(
      const std::vector<std::pair<secure::Ciphertext, secure::Ciphertext>>& items) {
    counts_.secure_mul += items.size();
    ++counts_.secure_mul_dispatches;
    return ops_.secureMulBatch(items);
  }
  secure::EncryptedBit greater(const secure::Ciphertext& a,
                                const secure::Ciphertext& b) {
    ++counts_.secure_compare;
    ++counts_.secure_compare_dispatches;
    return ops_.greaterThan(a, b);
  }
  std::vector<secure::EncryptedBit> greaterBatch(
      const std::vector<std::pair<secure::Ciphertext, secure::Ciphertext>>& items) {
    counts_.secure_compare += items.size();
    ++counts_.secure_compare_dispatches;
    return ops_.greaterThanBatch(items);
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
  secure::EncryptedBit orBitExclusive(const secure::EncryptedBit& a,
                                      const secure::EncryptedBit& b) {
    ++counts_.scalar_mul;
    ++counts_.add;
    return ops_.bitOrExclusive(a, b);
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
  std::vector<secure::Ciphertext> row_cost;
  std::vector<secure::Ciphertext> row_linear;
  std::vector<secure::Ciphertext> row_c12;
  std::vector<secure::Ciphertext> row_c3;
  secure::Ciphertext total;
  secure::Ciphertext c12;
  secure::Ciphertext c3;
  secure::Ciphertext linear;
  mutable std::optional<secure::EncryptedBit> feasible_cache;
  mutable std::optional<secure::Ciphertext> fitness_cache;
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
    stats_.rows = request_.costs.size();
    stats_.population = config_.population;
    stats_.generations = config_.generations;
    stats_.elitism = config_.elitism;
    stats_.tournament_size = config_.tournament_size;
    for (const auto& row : request_.costs)
      for (const auto& method : row.methods)
        if (method) ++stats_.available_methods;
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
    result.stats.extrapolated_410x1000 = multiplyCounts(
        result.stats.extrapolated_256x1000, 410ULL);
    result.stats.extrapolated_410x1000 = divideCounts(
        result.stats.extrapolated_410x1000, 256ULL);
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
            ceilDivide(value.secure_compare, divisor), ceilDivide(value.secure_select, divisor),
            ceilDivide(value.secure_mul_dispatches, divisor),
            ceilDivide(value.secure_compare_dispatches, divisor)};
  }
  static std::uint64_t saturatedMultiply(std::uint64_t value, std::uint64_t factor) {
    return factor && value > std::numeric_limits<std::uint64_t>::max() / factor
               ? std::numeric_limits<std::uint64_t>::max() : value * factor;
  }
  static ConfidentialScalableOperationCounts multiplyCounts(
      const ConfidentialScalableOperationCounts& value, std::uint64_t factor) {
    return {saturatedMultiply(value.encrypt_constant, factor), saturatedMultiply(value.add, factor),
            saturatedMultiply(value.scalar_mul, factor), saturatedMultiply(value.secure_mul, factor),
            saturatedMultiply(value.secure_compare, factor), saturatedMultiply(value.secure_select, factor),
            saturatedMultiply(value.secure_mul_dispatches, factor),
            saturatedMultiply(value.secure_compare_dispatches, factor)};
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
            saturatedAdd(a.secure_compare, b.secure_compare), saturatedAdd(a.secure_select, b.secure_select),
            saturatedAdd(a.secure_mul_dispatches, b.secure_mul_dispatches),
            saturatedAdd(a.secure_compare_dispatches, b.secure_compare_dispatches)};
  }
  static ConfidentialScalableOperationCounts subtractCounts(
      const ConfidentialScalableOperationCounts& a,
      const ConfidentialScalableOperationCounts& b) {
    return {a.encrypt_constant - b.encrypt_constant, a.add - b.add,
            a.scalar_mul - b.scalar_mul, a.secure_mul - b.secure_mul,
            a.secure_compare - b.secure_compare,
            a.secure_select - b.secure_select,
            a.secure_mul_dispatches - b.secure_mul_dispatches,
            a.secure_compare_dispatches - b.secure_compare_dispatches};
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
    value.feasible_cache.reset();
    value.fitness_cache.reset();
    value.total = zero_;
    value.c12 = zero_;
    value.c3 = zero_;
    value.linear = zero_;
    value.row_cost.assign(request_.costs.size(), zero_);
    value.row_linear.assign(request_.costs.size(), zero_);
    value.row_c12.assign(request_.costs.size(), zero_);
    value.row_c3.assign(request_.costs.size(), zero_);
    for (std::size_t row = 0; row < request_.costs.size(); ++row) {
      std::vector<std::pair<secure::Ciphertext, secure::Ciphertext>> products;
      std::vector<std::size_t> methods;
      for (std::size_t method = 0; method < 3; ++method)
        if (request_.costs[row].methods[method]) {
          methods.push_back(method);
          products.emplace_back(value.genes[row][method],
                                *request_.costs[row].methods[method]);
        }
      const auto chosen_products = ops_.mulBatch(products);
      for (std::size_t index = 0; index < methods.size(); ++index) {
        const auto method = methods[index];
        const auto& chosen = chosen_products[index];
        value.total = ops_.add(value.total, chosen);
        value.row_cost[row] = ops_.add(value.row_cost[row], chosen);
        if (method < 2)
          value.c12 = ops_.add(value.c12, chosen),
          value.row_c12[row] = ops_.add(value.row_c12[row], chosen);
        else
          value.c3 = ops_.add(value.c3, chosen),
          value.row_c3[row] = ops_.add(value.row_c3[row], chosen);
        const auto contribution = ops_.scalar(
            chosen, method < 2 ? scale_ - request_.threshold_scaled
                               : -request_.threshold_scaled);
        value.linear = ops_.add(value.linear, contribution);
        value.row_linear[row] = ops_.add(value.row_linear[row], contribution);
      }
    }
    return value;
  }

  secure::EncryptedBit feasible(const Individual& value) {
    if (value.feasible_cache) return *value.feasible_cache;
    const auto linear_nonnegative = ops_.notBit(ops_.less(value.linear, zero_));
    const auto has_method3 = ops_.greater(value.c3, zero_);
    const auto nonzero_total = ops_.greater(value.total, zero_);
    value.feasible_cache = ops_.andBit(ops_.andBit(linear_nonnegative, has_method3), nonzero_total);
    return *value.feasible_cache;
  }

  secure::Ciphertext fitness(const Individual& value) {
    if (value.fitness_cache) return *value.fitness_cache;
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
    value.fitness_cache = ops_.add(ops_.add(base, constant),
                                   ops_.add(weighted_violation, missing_cost));
    return *value.fitness_cache;
  }

  secure::EncryptedBit lexLess(const Individual& a, const Individual& b) {
    auto prefix_equal = ops_.notBit(ops_.greater(zero_, zero_));
    auto lex_less = ops_.greater(zero_, zero_);
    std::vector<std::pair<secure::Ciphertext, secure::Ciphertext>> relations;
    relations.reserve(a.genes.size() * 2);
    for (std::size_t row = 0; row < a.genes.size(); ++row) {
      auto a_index = ops_.add(a.genes[row][1], ops_.scalar(a.genes[row][2], 2));
      auto b_index = ops_.add(b.genes[row][1], ops_.scalar(b.genes[row][2], 2));
      relations.emplace_back(b_index, a_index);
      relations.emplace_back(a_index, b_index);
    }
    const auto compared = ops_.greaterBatch(relations);
    for (std::size_t row = 0; row < a.genes.size(); ++row) {
      const auto less = compared[row * 2];
      const auto equal = ops_.notBit(ops_.orBitExclusive(
          compared[row * 2 + 1], compared[row * 2]));
      lex_less = ops_.orBit(lex_less, ops_.andBit(prefix_equal, less));
      prefix_equal = ops_.andBit(prefix_equal, equal);
    }
    return lex_less;
  }

  secure::EncryptedBit better(const Individual& a, const Individual& b) {
    const auto feasible_a = feasible(a);
    const auto feasible_b = feasible(b);
    const auto a_only_feasible = ops_.andBit(feasible_a, ops_.notBit(feasible_b));
    const auto total_above = ops_.greater(a.total, b.total);
    const auto total_below = ops_.greater(b.total, a.total);
    const auto total_less = total_below;
    const auto total_equal = ops_.notBit(ops_.orBitExclusive(total_above, total_below));
    const auto ratio_less = ops_.less(a.linear, b.linear);
    const auto ratio_equal = ops_.notBit(ops_.orBitExclusive(
        ops_.greater(a.linear, b.linear), ops_.greater(b.linear, a.linear)));
    const auto tie_lex = ops_.andBit(ratio_equal, lexLess(a, b));
    const auto feasible_better = ops_.orBit(total_less,
        ops_.andBit(total_equal, ops_.orBit(ratio_less, tie_lex)));
    const auto fitness_a = fitness(a);
    const auto fitness_b = fitness(b);
    const auto infeasible_less = ops_.less(fitness_a, fitness_b);
    const auto infeasible_equal = ops_.notBit(ops_.orBitExclusive(
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
    selected.row_cost.resize(yes.row_cost.size());
    selected.row_linear.resize(yes.row_linear.size());
    selected.row_c12.resize(yes.row_c12.size());
    selected.row_c3.resize(yes.row_c3.size());
    for (std::size_t row = 0; row < yes.genes.size(); ++row)
      for (std::size_t method = 0; method < 3; ++method)
        selected.genes[row][method] = ops_.select(condition, yes.genes[row][method],
                                                   no.genes[row][method]);
    for (std::size_t row = 0; row < yes.row_cost.size(); ++row) {
      selected.row_cost[row] = ops_.select(condition, yes.row_cost[row], no.row_cost[row]);
      selected.row_linear[row] = ops_.select(condition, yes.row_linear[row], no.row_linear[row]);
      selected.row_c12[row] = ops_.select(condition, yes.row_c12[row], no.row_c12[row]);
      selected.row_c3[row] = ops_.select(condition, yes.row_c3[row], no.row_c3[row]);
    }
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
    for (std::size_t round = 0; round < rounds; ++round) {
      const auto was_feasible = feasible(value);
      auto selected_cost = zero_;
      auto selected_linear = zero_;
      auto selected_id = zero_;
      auto have_selected = ops_.greater(zero_, zero_);
      const auto need_method3 = ops_.notBit(ops_.greater(value.c3, zero_));
      auto best3_cost = zero_;
      auto best3_linear = zero_;
      auto best3_id = zero_;
      auto have3 = ops_.greater(zero_, zero_);
      auto method3_count = zero_;
      for (const auto& row : value.genes)
        method3_count = ops_.add(method3_count, row[2]);
      for (std::size_t row = 0; row < request_.costs.size(); ++row) {
        const auto current_cost = value.row_cost[row];
        const auto current_linear = value.row_linear[row];
        for (std::size_t method = 0; method < 3; ++method) {
          if (!request_.costs[row].methods[method]) continue;
          const auto delta_cost = ops_.sub(*request_.costs[row].methods[method], current_cost);
          const auto target_linear = ops_.scalar(*request_.costs[row].methods[method],
              method < 2 ? scale_ - request_.threshold_scaled : -request_.threshold_scaled);
          const auto delta_linear = ops_.sub(target_linear, current_linear);
          const auto positive_delta = ops_.greater(delta_linear, zero_);
          auto valid = positive_delta;
          // A non-method3 target may not remove the sole selected method3.
          if (method != 2) {
            const auto remaining = ops_.sub(method3_count, value.genes[row][2]);
            valid = ops_.andBit(valid, ops_.greater(remaining, zero_));
          }
          if (method == 2) {
            const auto better3 = ops_.less(delta_cost, best3_cost);
            const auto replace3 = ops_.orBit(ops_.notBit(have3), better3);
            best3_cost = ops_.select(replace3, delta_cost, best3_cost);
            best3_linear = ops_.select(replace3, delta_linear, best3_linear);
            best3_id = ops_.select(replace3,
                                   ops_.constant(static_cast<std::int64_t>(row * 3 + method)),
                                   best3_id);
            have3 = ops_.orBit(have3, replace3);
            valid = ops_.andBit(valid, ops_.notBit(need_method3));
          }
          const auto lhs = ops_.mul(delta_cost, selected_linear);
          const auto rhs = ops_.mul(selected_cost, delta_linear);
          const auto smaller = ops_.less(lhs, rhs);
          const auto replace = ops_.andBit(valid,
              ops_.orBit(ops_.notBit(have_selected), smaller));
          selected_cost = ops_.select(replace, delta_cost, selected_cost);
          selected_linear = ops_.select(replace, delta_linear, selected_linear);
          selected_id = ops_.select(replace,
                                    ops_.constant(static_cast<std::int64_t>(row * 3 + method)),
                                    selected_id);
          have_selected = ops_.orBit(have_selected, valid);
        }
      }
      selected_id = ops_.select(need_method3, best3_id, selected_id);
      selected_cost = ops_.select(need_method3, best3_cost, selected_cost);
      selected_linear = ops_.select(need_method3, best3_linear, selected_linear);
      have_selected = ops_.orBit(have_selected, ops_.andBit(need_method3, have3));
      const auto apply = ops_.andBit(ops_.notBit(was_feasible), have_selected);
      // A second fixed public scan decodes the encrypted id only through
      // equality masks; no id/bit is revealed to the host.
      for (std::size_t row = 0; row < request_.costs.size(); ++row)
        for (std::size_t method = 0; method < 3; ++method) {
          if (!request_.costs[row].methods[method]) continue;
          const auto id = ops_.constant(static_cast<std::int64_t>(row * 3 + method));
          const auto eq = ops_.notBit(ops_.orBitExclusive(
              ops_.greater(selected_id, id), ops_.greater(id, selected_id)));
          const auto mask = ops_.mul(apply.ciphertext(), eq.ciphertext());
          const auto old_cost = value.row_cost[row];
          const auto old_linear = value.row_linear[row];
          const auto target_linear = ops_.scalar(*request_.costs[row].methods[method],
              method < 2 ? scale_ - request_.threshold_scaled
                         : -request_.threshold_scaled);
          const auto delta_linear_actual = ops_.sub(target_linear, old_linear);
          const auto delta_cost_actual = ops_.sub(*request_.costs[row].methods[method], old_cost);
          const auto delta_c12 = ops_.sub(method < 2
                                              ? *request_.costs[row].methods[method]
                                              : zero_, value.row_c12[row]);
          const auto delta_c3 = ops_.sub(method == 2
                                             ? *request_.costs[row].methods[method]
                                             : zero_, value.row_c3[row]);
          value.total = ops_.add(value.total, ops_.mul(mask, delta_cost_actual));
          value.linear = ops_.add(value.linear, ops_.mul(mask, delta_linear_actual));
          value.row_cost[row] = ops_.add(old_cost, ops_.mul(mask, delta_cost_actual));
          value.row_linear[row] = ops_.add(old_linear, ops_.mul(mask, delta_linear_actual));
          value.row_c12[row] = ops_.add(value.row_c12[row], ops_.mul(mask, delta_c12));
          value.row_c3[row] = ops_.add(value.row_c3[row], ops_.mul(mask, delta_c3));
          value.c12 = ops_.add(value.c12, ops_.mul(mask, delta_c12));
          value.c3 = ops_.add(value.c3, ops_.mul(mask, delta_c3));
          for (std::size_t target_method = 0; target_method < 3; ++target_method) {
            const auto target = ops_.constant(target_method == method);
            const auto delta = ops_.sub(target, value.genes[row][target_method]);
            value.genes[row][target_method] = ops_.add(
                value.genes[row][target_method], ops_.mul(mask, delta));
          }
        }
      value.feasible_cache.reset();
      value.fitness_cache.reset();
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
