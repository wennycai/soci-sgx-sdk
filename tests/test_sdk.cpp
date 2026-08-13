#include "soci/soci.hpp"
#include "soci/optimization.hpp"
#include <cassert>
#include <filesystem>
#include <iostream>
#include <cmath>
#include <functional>
#include <random>

static void check_against_brute_force(){
  using namespace soci::optimization;
  std::mt19937 rng(7);
  const std::vector<double> thresholds{0.0,0.6,0.9,0.999999};
  for(int sample=0;sample<80;sample++){
    CostMatrix matrix(5);
    std::vector<std::array<std::optional<int>,3>> values(5);
    for(int i=0;i<5;i++)for(int j=0;j<3;j++){
      if((rng()%5)!=0){int c=1+rng()%20;values[i][j]=c;matrix[i][j]=std::to_string(c);}
    }
    for(int i=0;i<5;i++)if(!values[i][0]&&!values[i][1]&&!values[i][2]){values[i][0]=1;matrix[i][0]="1";}
    double threshold=thresholds[sample%thresholds.size()],best=1e100;
    std::vector<int> choice(5);
    std::function<void(int)> visit=[&](int i){
      if(i<5){for(int j=0;j<3;j++)if(values[i][j]){choice[i]=j;visit(i+1);}return;}
      double c12=0,c3=0;
      for(int k=0;k<5;k++)(choice[k]<2?c12:c3)+=*values[k][choice[k]];
      double total=c12+c3,ratio=c12/total;
      if(ratio>=threshold&&ratio<1)best=std::min(best,total);
    };
    visit(0);
    try{
      auto result=optimize_plain(matrix,std::to_string(threshold));
      assert(best<1e99&&std::abs(result.total_cost-best)<1e-9);
    }catch(const OptimizationError&e){assert(e.status()==Status::no_feasible_solution&&best>1e99);}
  }
}
int main(){
  check_against_brute_force();
  auto dir=std::filesystem::temp_directory_path()/"soci-sdk-test";
  std::filesystem::remove_all(dir);
  {
    soci::Runtime r(dir.string()); assert(r.mode()==SOCI_MODE_OFF);
    r.create_key("unit");
    auto a=r.encrypt("-12"),b=r.encrypt("7");
    assert(r.decrypt(a)=="-12");
    assert(r.decrypt(r.add(a,b))=="-5");
    assert(r.decrypt(r.scalar_mul(b,"-3"))=="-21");
    size_t n=0;
#if SOCI_ENABLE_EXPERIMENTAL_PROTOCOLS
    assert(soci_secure_sign_bit(r.native(),a.data(),a.size(),nullptr,&n)==SOCI_BUFFER_TOO_SMALL);
#else
    assert(soci_secure_sign_bit(r.native(),a.data(),a.size(),nullptr,&n)==SOCI_INVALID_STATE);
#endif
  }
  {
    soci::Runtime r(dir.string());r.open_key("unit");
    assert(r.decrypt(r.encrypt("123456789012345678901234567890"))=="123456789012345678901234567890");
    using namespace soci::optimization;
    CostMatrix costs={
      CostRow{Cost{"10.5"},Cost{"12.1"},Cost{"8.4"}},
      CostRow{Cost{"20.0"},std::nullopt,Cost{"15.2"}},
      CostRow{std::nullopt,Cost{"18.4"},Cost{"11.6"}}};
    auto reference=optimize_plain(costs,"0.6");
    auto encrypted=Optimizer(r).optimize(costs,"0.6");
    assert(reference.solution==encrypted.solution);
    assert(reference.solution.size()==3);
    assert(reference.ratio>=0.6&&reference.ratio<1.0);
    assert(std::abs(reference.total_cost-encrypted.total_cost)<1e-9);
    auto tie=optimize_plain({CostRow{Cost{"1"},Cost{"1"},Cost{"1"}},
                             CostRow{Cost{"1"},Cost{"1"},Cost{"1"}}},"0");
    assert((tie.solution==std::vector<int>{3,3}));
    bool no_solution=false;
    try{optimize_plain({CostRow{}},"0.6");}catch(const OptimizationError&e){no_solution=e.status()==Status::no_feasible_solution;}
    assert(no_solution);
  }
  std::filesystem::remove_all(dir);
  std::cout<<"all tests passed\n";
}
