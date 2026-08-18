#include "soci/scalable_optimizer.hpp"
#include "fixed_point.hpp"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <limits>
#include <numeric>
#include <random>
#include <stdexcept>

namespace soci::optimization {
namespace {
constexpr std::int64_t kScale=1'000'000;
using Clock=std::chrono::steady_clock;


struct Model {
  std::vector<std::array<std::optional<std::int64_t>,3>> costs;
  std::vector<std::vector<std::uint8_t>> available;
  std::int64_t threshold{};
  __int128 max_total{};
};

Model encode(const CostMatrix& input,const std::string& threshold){
  if(input.empty())throw OptimizationError(Status::invalid_argument,"cost matrix must not be empty");
  Model model;model.threshold=detail::parse_fixed_point(threshold,true);model.costs.reserve(input.size());
  model.available.reserve(input.size());bool any_method3=false;
  for(const auto&source:input){
    std::array<std::optional<std::int64_t>,3> row;std::vector<std::uint8_t> available;
    std::int64_t maximum=0;
    for(std::uint8_t method=0;method<3;++method)if(source[method]){
      row[method]=detail::parse_fixed_point(*source[method],false);available.push_back(method);
      maximum=std::max(maximum,*row[method]);if(method==2)any_method3=true;
    }
    if(available.empty())throw OptimizationError(Status::no_feasible_solution,"each material needs an available method");
    model.max_total+=maximum;model.costs.push_back(row);
    model.available.push_back(std::move(available));
  }
  detail::validate_aggregate(model.max_total);
  if(!any_method3)throw OptimizationError(Status::no_feasible_solution,"ratio requires an available method3");
  return model;
}

struct Individual {
  std::vector<std::uint8_t> genes;
  std::int64_t total{},c12{},c3{};
  __int128 linear{};
  long double fitness{};
  bool feasible{};
};

void evaluate(const Model&model,Individual&x,long double penalty){
  x.total=x.c12=x.c3=0;x.linear=0;
  for(std::size_t i=0;i<x.genes.size();++i){const auto method=x.genes[i];const auto c=*model.costs[i][method];x.total+=c;if(method<2){x.c12+=c;x.linear+=(__int128)(kScale-model.threshold)*c;}else{x.c3+=c;x.linear-=(__int128)model.threshold*c;}}
  x.feasible=x.linear>=0&&x.c3>0&&x.total>0;
  const long double violation=x.linear<0?static_cast<long double>(-x.linear)/kScale:0;
  const long double missing_c3=x.c3==0?static_cast<long double>(model.max_total+1):0;
  x.fitness=static_cast<long double>(x.total)+(x.feasible?0:penalty*(1+violation+missing_c3));
}

bool order(const Model&model,const Individual&a,const Individual&b){
  if(a.feasible!=b.feasible)return a.feasible;
  if(a.feasible){
    if(a.total!=b.total)return a.total<b.total;
    // Both linear values are non-negative. Compare (ratio - T) exactly,
    // matching Exact B&B's fixed-point rational tie-break.
    const auto lhs=a.linear*static_cast<__int128>(b.total);
    const auto rhs=b.linear*static_cast<__int128>(a.total);
    if(lhs!=rhs)return lhs<rhs;
  }else if(a.fitness!=b.fitness)return a.fitness<b.fitness;
  return a.genes<b.genes;
}

bool repair(const Model&model,Individual&x,long double penalty){
  evaluate(model,x,penalty);
  if(x.c3==0){
    bool found=false;std::size_t best_row=0;std::int64_t best_delta=0;
    for(std::size_t i=0;i<x.genes.size();++i)if(model.costs[i][2]){
      const auto delta=*model.costs[i][2]-*model.costs[i][x.genes[i]];
      if(!found||delta<best_delta){found=true;best_row=i;best_delta=delta;}
    }
    if(!found)return false;x.genes[best_row]=2;evaluate(model,x,penalty);
  }
  while(x.linear<0){
    const auto method3_count=std::count(x.genes.begin(),x.genes.end(),2);
    bool found=false;std::size_t best_row=0;std::uint8_t best_method=0;
    long double best_ratio=std::numeric_limits<long double>::infinity();
    std::int64_t best_cost_delta=0;__int128 best_linear_delta=0;
    for(std::size_t i=0;i<x.genes.size();++i){
      const auto old=x.genes[i];
      const auto old_cost=*model.costs[i][old];
      const __int128 old_linear=old<2?(__int128)(kScale-model.threshold)*old_cost:-(__int128)model.threshold*old_cost;
      for(const auto method:model.available[i])if(method!=old){
        if(old==2&&method!=2&&method3_count==1)continue;
        const auto cost=*model.costs[i][method];
        const __int128 next_linear=method<2?(__int128)(kScale-model.threshold)*cost:-(__int128)model.threshold*cost;
        const auto delta_linear=next_linear-old_linear;if(delta_linear<=0)continue;
        const auto delta_cost=cost-old_cost;
        const long double ratio=static_cast<long double>(delta_cost)/static_cast<long double>(delta_linear);
        if(!found||ratio<best_ratio||(ratio==best_ratio&&std::pair{i,method}<std::pair{best_row,best_method})){
          found=true;best_ratio=ratio;best_row=i;best_method=method;
          best_cost_delta=delta_cost;best_linear_delta=delta_linear;
        }
      }
    }
    if(!found)return false;
    x.genes[best_row]=best_method;x.total+=best_cost_delta;x.linear+=best_linear_delta;
    evaluate(model,x,penalty);
  }
  return x.feasible;
}
}  // namespace

ScalableOptimizer::ScalableOptimizer(GeneticSolverConfig config):config_(config){
  if(config_.population<2||config_.generations==0||config_.elitism==0||
     config_.elitism>=config_.population||config_.tournament_size==0||
     config_.crossover_rate<0||config_.crossover_rate>1||
     config_.mutation_rate<0||config_.mutation_rate>1||
     config_.infeasible_penalty_multiplier<=0)
    throw std::invalid_argument("invalid genetic solver configuration");
}

ScalableOptimizationResult ScalableOptimizer::optimize(
    const CostMatrix& costs,const std::string& threshold)const{
  const auto start=Clock::now();const auto model=encode(costs,threshold);
  std::mt19937_64 rng(config_.seed);std::uniform_real_distribution<double> unit(0,1);
  const long double penalty=(static_cast<long double>(model.max_total)+1)*
                            config_.infeasible_penalty_multiplier;
  std::size_t candidates=0,pre_repair_feasible=0,repair_attempts=0,repair_successes=0;
  auto prepare=[&](Individual&x){
    evaluate(model,x,penalty);++candidates;
    if(x.feasible){++pre_repair_feasible;return;}
    ++repair_attempts;
    if(repair(model,x,penalty))++repair_successes;
    evaluate(model,x,penalty);
  };
  auto random_individual=[&]{Individual x;x.genes.resize(model.costs.size());for(std::size_t i=0;i<x.genes.size();++i){const auto&available=model.available[i];x.genes[i]=available[rng()%available.size()];}prepare(x);return x;};
  std::vector<Individual> population;population.reserve(config_.population);
  Individual cheapest;cheapest.genes.resize(model.costs.size());
  for(std::size_t i=0;i<model.costs.size();++i)cheapest.genes[i]=*std::min_element(model.available[i].begin(),model.available[i].end(),[&](auto a,auto b){return *model.costs[i][a]<*model.costs[i][b];});
  prepare(cheapest);population.push_back(cheapest);
  while(population.size()<config_.population)population.push_back(random_individual());
  Individual best;bool have_best=false;std::size_t best_generation=0;
  std::vector<double> convergence(config_.generations+1,
                                  std::numeric_limits<double>::quiet_NaN());
  auto retain_best=[&](std::size_t generation){for(const auto&x:population)if(x.feasible&&(!have_best||order(model,x,best))){best=x;have_best=true;best_generation=generation;}
    if(have_best)convergence[generation]=static_cast<double>(best.total)/kScale;};
  retain_best(0);
  for(std::size_t generation=1;generation<=config_.generations;++generation){
    std::sort(population.begin(),population.end(),[&](const auto&a,const auto&b){return order(model,a,b);});std::vector<Individual> next;
    next.reserve(config_.population);for(std::size_t i=0;i<config_.elitism;++i)next.push_back(population[i]);
    auto select=[&]()->const Individual&{std::size_t winner=rng()%population.size();for(std::size_t k=1;k<config_.tournament_size;++k){const auto challenger=rng()%population.size();if(order(model,population[challenger],population[winner]))winner=challenger;}return population[winner];};
    while(next.size()<config_.population){Individual child=select();const auto&other=select();if(unit(rng)<config_.crossover_rate)for(std::size_t i=0;i<child.genes.size();++i)if(rng()&1)child.genes[i]=other.genes[i];for(std::size_t i=0;i<child.genes.size();++i)if(unit(rng)<config_.mutation_rate&&model.available[i].size()>1){auto method=model.available[i][rng()%model.available[i].size()];if(method==child.genes[i])method=model.available[i][(std::find(model.available[i].begin(),model.available[i].end(),method)-model.available[i].begin()+1)%model.available[i].size()];child.genes[i]=method;}prepare(child);next.push_back(std::move(child));}
    population=std::move(next);retain_best(generation);
  }
  if(!have_best)throw OptimizationError(Status::no_feasible_solution,"GA found no feasible assignment");
  const auto feasible=std::count_if(population.begin(),population.end(),[](const auto&x){return x.feasible;});
  ScalableOptimizationResult result;result.solution.reserve(best.genes.size());for(auto method:best.genes)result.solution.push_back(method+1);result.total_cost=static_cast<double>(best.total)/kScale;result.ratio=static_cast<double>(best.c12)/static_cast<double>(best.total);result.generation=best_generation;result.feasible_rate=static_cast<double>(feasible)/population.size();result.pre_repair_feasible_rate=static_cast<double>(pre_repair_feasible)/candidates;result.repair_success_rate=repair_attempts==0?1.0:static_cast<double>(repair_successes)/repair_attempts;result.runtime_seconds=std::chrono::duration<double>(Clock::now()-start).count();result.convergence_costs=std::move(convergence);return result;
}

}  // namespace soci::optimization
