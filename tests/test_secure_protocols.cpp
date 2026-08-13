#include "soci/soci.hpp"
#include <cassert>
#include <filesystem>
#include <iostream>
#include <tuple>
#include <vector>

int main(){
  auto dir=std::filesystem::temp_directory_path()/"soci-secure-protocol-test";
  std::filesystem::remove_all(dir);soci::Runtime r(dir.string());r.create_key("protocol");
  for(auto [x,y]:std::vector<std::pair<long long,long long>>{{7,9},{-7,9},{7,-9},{-7,-9},{0,99}}){
    auto product=r.decrypt(r.secure_mul(r.encrypt(std::to_string(x)),r.encrypt(std::to_string(y))));
    assert(product==std::to_string(x*y));
  }
  for(long long x:std::vector<long long>{-1000,-1,0,1,1000}){
    auto encrypted=r.encrypt(std::to_string(x));
    assert(r.decrypt(r.secure_sign_bit(encrypted))==(x<0?"1":"0"));
    assert(r.decrypt(r.secure_abs(encrypted))==std::to_string(x<0?-x:x));
  }
  for(auto [x,y]:std::vector<std::pair<long long,long long>>{{0,1},{1,1},{120,7},{999,31},{2047,13}}){
    auto qr=r.secure_div(r.encrypt(std::to_string(x)),r.encrypt(std::to_string(y)));
    assert(r.decrypt(qr.first)==std::to_string(x/y));
    assert(r.decrypt(qr.second)==std::to_string(x%y));
  }
  bool zero=false;try{r.secure_div(r.encrypt("7"),r.encrypt("0"));}catch(const soci::Error&){zero=true;}assert(zero);
  std::filesystem::remove_all(dir);std::cout<<"SOCI-plus OFF secure protocol tests passed\n";
}
