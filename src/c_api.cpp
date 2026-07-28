#include "internal.hpp"
#include <cstring>
#include <functional>
using namespace soci::detail;
namespace {
soci_status_t run(soci_runtime_t*r,const std::function<void()>&f){if(!r)return SOCI_INVALID_ARGUMENT;try{std::lock_guard<std::mutex>g(r->mu);if(r->closed)throw std::logic_error("runtime closed");f();r->error.clear();return SOCI_OK;}catch(const std::invalid_argument&e){r->error=e.what();return SOCI_INVALID_ARGUMENT;}catch(const std::logic_error&e){r->error=e.what();return SOCI_INVALID_STATE;}catch(const std::filesystem::filesystem_error&e){r->error=e.what();return SOCI_IO_ERROR;}catch(const std::exception&e){r->error=e.what();return SOCI_CRYPTO_ERROR;}catch(...){r->error="unknown internal error";return SOCI_INTERNAL_ERROR;}}
void need(soci_runtime_t*r){if(!r->key)throw std::logic_error("no key is open");}
std::filesystem::path path(soci_runtime_t*r,const char*id){if(!id||!valid_id(id))throw std::invalid_argument("invalid key id");return r->root/(std::string(id)+".skey");}
void output(const std::vector<uint8_t>&v,uint8_t*out,size_t*n){if(!n)throw std::invalid_argument("null output length");if(!out||*n<v.size()){*n=v.size();throw std::length_error("buffer too small");}memcpy(out,v.data(),v.size());*n=v.size();}
soci_status_t bout(soci_runtime_t*r,const std::function<std::vector<uint8_t>()>&f,uint8_t*o,size_t*n){auto s=run(r,[&]{output(f(),o,n);});if(r&&r->error=="buffer too small")return SOCI_BUFFER_TOO_SMALL;return s;}
mpz_class ct(soci_runtime_t*r,const uint8_t*p,size_t n){return decode_object(p,n,1,r->mode);}
std::vector<uint8_t> encct(soci_runtime_t*r,const mpz_class&z){return encode_object(1,r->mode,z);}
soci_status_t disabled(soci_runtime_t*r){return run(r,[&]{throw std::logic_error("experimental protocol disabled by default");});}
}
extern "C" {
soci_status_t soci_create_key(soci_runtime_t*r,const char*id,uint32_t bits,soci_role_t role){return run(r,[&]{if(r->mode!=SOCI_MODE_OFF)throw std::logic_error("SGX keygen adapter required");if(role!=SOCI_ROLE_FULL)throw std::logic_error("OFF test backend supports FULL role only");auto k=std::make_unique<Key>();keygen(bits,*k);k->info={};k->info.struct_version=1;k->info.modulus_bits=bits;k->info.key_version=1;k->info.role=role;k->info.runtime_mode=r->mode;strncpy(k->info.key_id,id,sizeof(k->info.key_id)-1);save_off_key(path(r,id),*k);r->key=std::move(k);});}
soci_status_t soci_open_key(soci_runtime_t*r,const char*id,soci_role_t role){return run(r,[&]{r->key=std::make_unique<Key>(load_off_key(path(r,id),r->mode,role));});}
soci_status_t soci_rotate_key(soci_runtime_t*r,const char*id){return run(r,[&]{need(r);if(std::string(r->key->info.key_id)!=id)throw std::invalid_argument("key id mismatch");uint64_t v=r->key->info.key_version+1;auto k=std::make_unique<Key>();keygen(r->key->info.modulus_bits,*k);k->info=r->key->info;k->info.key_version=v;save_off_key(path(r,id),*k);r->key=std::move(k);});}
soci_status_t soci_delete_key(soci_runtime_t*r,const char*id){return run(r,[&]{auto p=path(r,id);if(r->key&&std::string(r->key->info.key_id)==id)r->key.reset();if(!std::filesystem::remove(p))throw std::invalid_argument("key not found");});}
soci_status_t soci_get_key_info(soci_runtime_t*r,soci_key_info_t*out){return run(r,[&]{need(r);if(!out)throw std::invalid_argument("null key info");*out=r->key->info;});}
soci_status_t soci_export_public_key(soci_runtime_t*r,uint8_t*o,size_t*n){return bout(r,[&]{need(r);return encode_public(*r->key);},o,n);}
soci_status_t soci_encrypt(soci_runtime_t*r,const char*m,uint8_t*o,size_t*n){return bout(r,[&]{need(r);if(!m)throw std::invalid_argument("null plaintext");mpz_class z;if(z.set_str(m,10))throw std::invalid_argument("plaintext is not decimal");return encct(r,encrypt(r->key->pub,z,*r->rng));},o,n);}
soci_status_t soci_decrypt(soci_runtime_t*r,const uint8_t*p,size_t l,char*o,size_t*n){auto s=run(r,[&]{need(r);auto z=decrypt(*r->key,ct(r,p,l)).get_str();size_t q=z.size()+1;if(!n)throw std::invalid_argument("null output length");if(!o||*n<q){*n=q;throw std::length_error("buffer too small");}memcpy(o,z.c_str(),q);*n=q;});if(r&&r->error=="buffer too small")return SOCI_BUFFER_TOO_SMALL;return s;}
soci_status_t soci_add(soci_runtime_t*r,const uint8_t*a,size_t al,const uint8_t*b,size_t bl,uint8_t*o,size_t*n){return bout(r,[&]{need(r);return encct(r,(ct(r,a,al)*ct(r,b,bl))%r->key->pub.nsq);},o,n);}
soci_status_t soci_scalar_mul(soci_runtime_t*r,const uint8_t*a,size_t al,const char*k,uint8_t*o,size_t*n){return bout(r,[&]{need(r);if(!k)throw std::invalid_argument("null scalar");mpz_class x;if(x.set_str(k,10))throw std::invalid_argument("scalar is not decimal");auto c=ct(r,a,al);if(x<0){if(!mpz_invert(c.get_mpz_t(),c.get_mpz_t(),r->key->pub.nsq.get_mpz_t()))throw std::invalid_argument("ciphertext inverse failed");x=-x;}mpz_class z;mpz_powm(z.get_mpz_t(),c.get_mpz_t(),x.get_mpz_t(),r->key->pub.nsq.get_mpz_t());return encct(r,z);},o,n);}
soci_status_t soci_secure_mul(soci_runtime_t*r,const uint8_t*a,size_t al,const uint8_t*b,size_t bl,uint8_t*o,size_t*n){
#if SOCI_ENABLE_EXPERIMENTAL_PROTOCOLS
return bout(r,[&]{need(r);mpz_class av=decrypt(*r->key,ct(r,a,al)),bv=decrypt(*r->key,ct(r,b,bl));mpz_class z=av*bv;return encct(r,encrypt(r->key->pub,z,*r->rng));},o,n);
#else
return disabled(r);
#endif
}
soci_status_t soci_secure_compare(soci_runtime_t*r,const uint8_t*a,size_t al,const uint8_t*b,size_t bl,uint8_t*o,size_t*n){
#if SOCI_ENABLE_EXPERIMENTAL_PROTOCOLS
return bout(r,[&]{need(r);mpz_class z=decrypt(*r->key,ct(r,a,al))>decrypt(*r->key,ct(r,b,bl))?1:0;return encct(r,encrypt(r->key->pub,z,*r->rng));},o,n);
#else
return disabled(r);
#endif
}
soci_status_t soci_secure_sign_bit(soci_runtime_t*r,const uint8_t*a,size_t al,uint8_t*o,size_t*n){
#if SOCI_ENABLE_EXPERIMENTAL_PROTOCOLS
return bout(r,[&]{need(r);mpz_class z=decrypt(*r->key,ct(r,a,al))<0?1:0;return encct(r,encrypt(r->key->pub,z,*r->rng));},o,n);
#else
return disabled(r);
#endif
}
soci_status_t soci_secure_abs(soci_runtime_t*r,const uint8_t*a,size_t al,uint8_t*o,size_t*n){
#if SOCI_ENABLE_EXPERIMENTAL_PROTOCOLS
return bout(r,[&]{need(r);mpz_class z=decrypt(*r->key,ct(r,a,al));if(z<0)z=-z;return encct(r,encrypt(r->key->pub,z,*r->rng));},o,n);
#else
return disabled(r);
#endif
}
soci_status_t soci_secure_div(soci_runtime_t*r,const uint8_t*a,size_t al,const uint8_t*b,size_t bl,uint8_t*q,size_t*ql,uint8_t*rem,size_t*rl){
#if SOCI_ENABLE_EXPERIMENTAL_PROTOCOLS
{auto s=run(r,[&]{need(r);auto x=decrypt(*r->key,ct(r,a,al)),y=decrypt(*r->key,ct(r,b,bl));if(y==0)throw std::invalid_argument("division by zero");mpz_class qv=x/y,rv=x%y;auto qo=encct(r,encrypt(r->key->pub,qv,*r->rng)),ro=encct(r,encrypt(r->key->pub,rv,*r->rng));if(!ql||!rl)throw std::invalid_argument("null output length");if(!q||!rem||*ql<qo.size()||*rl<ro.size()){*ql=qo.size();*rl=ro.size();throw std::length_error("buffer too small");}memcpy(q,qo.data(),qo.size());memcpy(rem,ro.data(),ro.size());*ql=qo.size();*rl=ro.size();});if(r&&r->error=="buffer too small")return SOCI_BUFFER_TOO_SMALL;return s;}
#else
return disabled(r);
#endif
}
soci_status_t soci_start_cp_service(soci_runtime_t*r){return run(r,[&]{r->cp_running=true;});} soci_status_t soci_stop_cp_service(soci_runtime_t*r){return run(r,[&]{r->cp_running=false;});}
soci_status_t soci_start_csp_service(soci_runtime_t*r){return run(r,[&]{r->csp_running=true;});} soci_status_t soci_stop_csp_service(soci_runtime_t*r){return run(r,[&]{r->csp_running=false;});}
soci_status_t soci_health_check(soci_runtime_t*r){return run(r,[&]{});}
}
