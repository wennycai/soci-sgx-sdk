#include "internal.hpp"
#include <iostream>
#include <random>
#include <cstring>
namespace {
soci_mode_t compiled_mode(){
#if defined(SOCI_SGX_MODE)
  std::string m=SOCI_SGX_MODE;if(m=="SIM")return SOCI_MODE_SIM;if(m=="HW")return SOCI_MODE_HW;
#endif
  return SOCI_MODE_OFF;
}
}
extern "C" {
const char* soci_get_version(){return "0.1.0";}
soci_status_t soci_runtime_create(const char*dir,soci_runtime_t**out){if(!dir||!out)return SOCI_INVALID_ARGUMENT;try{auto r=std::make_unique<soci_runtime>();r->root=dir;r->mode=compiled_mode();auto rd=std::filesystem::weakly_canonical(r->root);std::filesystem::create_directories(rd);r->root=rd;r->rng=std::make_unique<gmp_randclass>(gmp_randinit_default);std::random_device d;r->rng->seed((mpz_class(d())<<64)+d());std::cerr<<"soci-sdk: runtime mode="<<(r->mode==0?"OFF":r->mode==1?"SIM":"HW")<<"\n";*out=r.release();return SOCI_OK;}catch(...){return SOCI_IO_ERROR;}}
void soci_runtime_close(soci_runtime_t*r){if(!r)return;{std::lock_guard<std::mutex>g(r->mu);r->closed=true;r->key.reset();r->rng.reset();}delete r;}
soci_mode_t soci_runtime_get_mode(const soci_runtime_t*r){return r?r->mode:SOCI_MODE_OFF;}
const char* soci_runtime_get_last_error(const soci_runtime_t*r){return r?r->error.c_str():"invalid runtime";}
}
