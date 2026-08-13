#include "soci/soci.hpp"
#include <cassert>
#include <filesystem>
#include <iostream>
#include <vector>

int main(){
  auto dir=std::filesystem::temp_directory_path()/"soci-scmp-test";
  std::filesystem::remove_all(dir);soci::Runtime runtime(dir.string());runtime.create_key("scmp");
  const std::vector<long long> values{-1000000,-121,-1,0,1,7,120,1000000};
  for(long long x:values)for(long long y:values){
    auto actual=runtime.decrypt(runtime.secure_compare(runtime.encrypt(std::to_string(x)),runtime.encrypt(std::to_string(y))));
    auto expected=x>y?"1":"0";
    if(actual!=expected){std::cerr<<"SCMP mismatch: "<<x<<" > "<<y<<" expected "<<expected<<" got "<<actual<<"\n";return 1;}
  }
  // Repeated calls exercise both hidden direction branches and fresh masks.
  for(int i=0;i<100;i++)assert(runtime.decrypt(runtime.secure_compare(runtime.encrypt("120"),runtime.encrypt("7")))=="1");
  std::filesystem::remove_all(dir);std::cout<<"SOCI-plus OFF SCMP tests passed\n";
}
