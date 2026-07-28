#include "soci/soci.hpp"
#include <cassert>
#include <filesystem>
#include <iostream>
int main(){
  auto dir=std::filesystem::temp_directory_path()/"soci-sdk-test";
  std::filesystem::remove_all(dir);
  {
    soci::Runtime r(dir.string()); assert(r.mode()==SOCI_MODE_OFF);
    r.create_key("unit");
    auto a=r.encrypt("-12"),b=r.encrypt("7");
    assert(r.decrypt(a)=="-12");
    assert(r.decrypt(r.add(a,b))=="-5");
    assert(r.decrypt(r.scalar_mul(b,"-3"))=="-21");
    size_t n=0;assert(soci_secure_sign_bit(r.native(),a.data(),a.size(),nullptr,&n)==SOCI_INVALID_STATE);
  }
  {
    soci::Runtime r(dir.string());r.open_key("unit");
    assert(r.decrypt(r.encrypt("123456789012345678901234567890"))=="123456789012345678901234567890");
  }
  std::filesystem::remove_all(dir);
  std::cout<<"all tests passed\n";
}
