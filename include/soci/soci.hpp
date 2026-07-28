#pragma once
#include "soci.h"
#include <stdexcept>
#include <string>
#include <vector>
namespace soci {
class Error : public std::runtime_error { public: using std::runtime_error::runtime_error; };
class Runtime {
 public:
  explicit Runtime(const std::string& dir) { check(soci_runtime_create(dir.c_str(), &p_)); }
  ~Runtime() { soci_runtime_close(p_); }
  Runtime(const Runtime&)=delete; Runtime& operator=(const Runtime&)=delete;
  soci_mode_t mode() const { return soci_runtime_get_mode(p_); }
  void create_key(const std::string& id, uint32_t bits=SOCI_SECURITY_128_MODULUS_BITS) { check(soci_create_key(p_,id.c_str(),bits,SOCI_ROLE_FULL)); }
  void open_key(const std::string& id) { check(soci_open_key(p_,id.c_str(),SOCI_ROLE_FULL)); }
  std::vector<uint8_t> encrypt(const std::string& m) { return bytes([&](uint8_t* b,size_t*n){return soci_encrypt(p_,m.c_str(),b,n);}); }
  std::string decrypt(const std::vector<uint8_t>& c) { size_t n=0; auto s=soci_decrypt(p_,c.data(),c.size(),nullptr,&n); if(s!=SOCI_BUFFER_TOO_SMALL)check(s); std::string o(n,'\0'); check(soci_decrypt(p_,c.data(),c.size(),o.data(),&n)); o.resize(n? n-1:0); return o; }
  std::vector<uint8_t> add(const std::vector<uint8_t>&a,const std::vector<uint8_t>&b) { return bytes([&](uint8_t*o,size_t*n){return soci_add(p_,a.data(),a.size(),b.data(),b.size(),o,n);}); }
  std::vector<uint8_t> scalar_mul(const std::vector<uint8_t>&a,const std::string&k) { return bytes([&](uint8_t*o,size_t*n){return soci_scalar_mul(p_,a.data(),a.size(),k.c_str(),o,n);}); }
  std::vector<uint8_t> secure_mul(const std::vector<uint8_t>&a,const std::vector<uint8_t>&b) { return bytes([&](uint8_t*o,size_t*n){return soci_secure_mul(p_,a.data(),a.size(),b.data(),b.size(),o,n);}); }
  std::vector<uint8_t> secure_compare(const std::vector<uint8_t>&a,const std::vector<uint8_t>&b) { return bytes([&](uint8_t*o,size_t*n){return soci_secure_compare(p_,a.data(),a.size(),b.data(),b.size(),o,n);}); }
  std::vector<uint8_t> secure_sign_bit(const std::vector<uint8_t>&a) { return bytes([&](uint8_t*o,size_t*n){return soci_secure_sign_bit(p_,a.data(),a.size(),o,n);}); }
  std::vector<uint8_t> secure_abs(const std::vector<uint8_t>&a) { return bytes([&](uint8_t*o,size_t*n){return soci_secure_abs(p_,a.data(),a.size(),o,n);}); }
  std::pair<std::vector<uint8_t>,std::vector<uint8_t>> secure_div(const std::vector<uint8_t>&a,const std::vector<uint8_t>&b) {
    size_t qn=0,rn=0;auto s=soci_secure_div(p_,a.data(),a.size(),b.data(),b.size(),nullptr,&qn,nullptr,&rn);
    if(s!=SOCI_BUFFER_TOO_SMALL)check(s);std::vector<uint8_t>q(qn),r(rn);
    check(soci_secure_div(p_,a.data(),a.size(),b.data(),b.size(),q.data(),&qn,r.data(),&rn));
    q.resize(qn);r.resize(rn);return {std::move(q),std::move(r)};
  }
  soci_runtime_t* native() const { return p_; }
 private:
  soci_runtime_t* p_{};
  void check(soci_status_t s) const { if(s!=SOCI_OK) throw Error(soci_runtime_get_last_error(p_)); }
  template<class F> std::vector<uint8_t> bytes(F f) { size_t n=0; auto s=f(nullptr,&n); if(s!=SOCI_BUFFER_TOO_SMALL)check(s); for(int i=0;i<3;i++){std::vector<uint8_t> o(n);s=f(o.data(),&n);if(s==SOCI_OK){o.resize(n);return o;}if(s!=SOCI_BUFFER_TOO_SMALL)check(s);}throw Error("output size changed repeatedly"); }
};
}
