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
mpz_class cpow(const mpz_class&ciphertext,const mpz_class&exponent,const mpz_class&modulus){mpz_class z;mpz_powm(z.get_mpz_t(),ciphertext.get_mpz_t(),exponent.get_mpz_t(),modulus.get_mpz_t());return z;}
mpz_class cinv(const mpz_class&ciphertext,const mpz_class&modulus){mpz_class z;if(!mpz_invert(z.get_mpz_t(),ciphertext.get_mpz_t(),modulus.get_mpz_t()))throw std::invalid_argument("ciphertext inverse failed");return z;}
mpz_class cadd(const mpz_class&a,const mpz_class&b,const mpz_class&modulus){return a*b%modulus;}
mpz_class soci_plus_less(soci_runtime_t*r,const mpz_class&x,const mpz_class&y){
  const auto&pub=r->key->pub;auto random128=[&]{mpz_class v=r->rng->get_z_bits(128);return v==0?mpz_class(1):v;};
  mpz_class r3=random128(),noise;do noise=random128();while(noise>=r3);
  mpz_class r4=pub.n/2-noise,d;bool pi=r->rng->get_z_bits(1)!=0;
  if(!pi){
    mpz_class difference=x*cpow(y,pub.n-1,pub.nsq)%pub.nsq;
    d=cpow(difference,r3,pub.nsq)*encrypt(pub,r3+r4,*r->rng)%pub.nsq;
  }else{
    mpz_class difference=y*cinv(x,pub.nsq)%pub.nsq;
    d=cpow(difference,r3,pub.nsq)*encrypt(pub,r4,*r->rng)%pub.nsq;
  }
  // OFF emulates CSP: only randomized D is decrypted. Convert the SDK signed
  // representation back to Z_N before applying the SOCI-plus half test.
  mpz_class visible=decrypt(*r->key,d);if(visible<0)visible+=pub.n;
  mpz_class encrypted_bit=encrypt(pub,visible>pub.n/2?0:1,*r->rng);
  return pi?encrypt(pub,1,*r->rng)*cinv(encrypted_bit,pub.nsq)%pub.nsq:encrypted_bit;
}
mpz_class soci_plus_mul(soci_runtime_t*r,const mpz_class&x,const mpz_class&y){
  const auto&pub=r->key->pub;auto random128=[&]{mpz_class v=r->rng->get_z_bits(128);return v==0?mpz_class(1):v;};
  mpz_class r1=random128(),r2=random128();
  mpz_class X=cadd(x,encrypt(pub,r1,*r->rng),pub.nsq),Y=cadd(y,encrypt(pub,r2,*r->rng),pub.nsq);
  // OFF emulates CSP and decrypts masked operands only.
  mpz_class masked_x=decrypt(*r->key,X),masked_y=decrypt(*r->key,Y);
  mpz_class product=encrypt(pub,masked_x*masked_y,*r->rng);
  product=cadd(product,cpow(x,pub.n-r2,pub.nsq),pub.nsq);
  product=cadd(product,cpow(y,pub.n-r1,pub.nsq),pub.nsq);
  return cadd(product,encrypt(pub,-r1*r2,*r->rng),pub.nsq);
}
mpz_class soci_plus_sign(soci_runtime_t*r,const mpz_class&x){return soci_plus_less(r,x,encrypt(r->key->pub,0,*r->rng));}
mpz_class soci_plus_abs(soci_runtime_t*r,const mpz_class&x){
  const auto&pub=r->key->pub;mpz_class sign=soci_plus_sign(r,x);
  mpz_class factor=cadd(encrypt(pub,1,*r->rng),cpow(sign,pub.n-2,pub.nsq),pub.nsq);
  return soci_plus_mul(r,factor,x);
}
std::pair<mpz_class,mpz_class> soci_plus_div(soci_runtime_t*r,mpz_class dividend,const mpz_class&divisor,unsigned bits){
  const auto&pub=r->key->pub;mpz_class quotient=encrypt(pub,0,*r->rng),one=encrypt(pub,1,*r->rng);
  for(unsigned step=bits;step-->0;){
    mpz_class shifted=cpow(divisor,mpz_class(1)<<step,pub.nsq);
    mpz_class less=soci_plus_less(r,dividend,shifted);
    mpz_class take=cadd(one,cpow(less,pub.n-1,pub.nsq),pub.nsq);
    quotient=cadd(quotient,cpow(take,mpz_class(1)<<step,pub.nsq),pub.nsq);
    mpz_class subtraction=soci_plus_mul(r,take,shifted);
    dividend=cadd(dividend,cpow(subtraction,pub.n-1,pub.nsq),pub.nsq);
  }
  return {quotient,dividend};
}
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
return bout(r,[&]{need(r);return encct(r,soci_plus_mul(r,ct(r,a,al),ct(r,b,bl)));},o,n);
#else
return disabled(r);
#endif
}
soci_status_t soci_secure_compare(soci_runtime_t*r,const uint8_t*a,size_t al,const uint8_t*b,size_t bl,uint8_t*o,size_t*n){
#if SOCI_ENABLE_EXPERIMENTAL_PROTOCOLS
return bout(r,[&]{need(r);auto av=ct(r,a,al),bv=ct(r,b,bl);return encct(r,soci_plus_less(r,bv,av));},o,n);
#else
return disabled(r);
#endif
}
soci_status_t soci_secure_sign_bit(soci_runtime_t*r,const uint8_t*a,size_t al,uint8_t*o,size_t*n){
#if SOCI_ENABLE_EXPERIMENTAL_PROTOCOLS
return bout(r,[&]{need(r);return encct(r,soci_plus_sign(r,ct(r,a,al)));},o,n);
#else
return disabled(r);
#endif
}
soci_status_t soci_secure_abs(soci_runtime_t*r,const uint8_t*a,size_t al,uint8_t*o,size_t*n){
#if SOCI_ENABLE_EXPERIMENTAL_PROTOCOLS
return bout(r,[&]{need(r);return encct(r,soci_plus_abs(r,ct(r,a,al)));},o,n);
#else
return disabled(r);
#endif
}
soci_status_t soci_secure_div(soci_runtime_t*r,const uint8_t*a,size_t al,const uint8_t*b,size_t bl,uint8_t*q,size_t*ql,uint8_t*rem,size_t*rl){
#if SOCI_ENABLE_EXPERIMENTAL_PROTOCOLS
{auto s=run(r,[&]{need(r);if(!ql||!rl)throw std::invalid_argument("null output length");size_t maximum=12+(2*r->key->info.modulus_bits+7)/8;if(!q||!rem){*ql=maximum;*rl=maximum;throw std::length_error("buffer too small");}auto x=ct(r,a,al),y=ct(r,b,bl);auto below_one=soci_plus_less(r,y,encrypt(r->key->pub,1,*r->rng));if(decrypt(*r->key,below_one)!=0)throw std::invalid_argument("divisor must be positive");auto qr=soci_plus_div(r,x,y,21);auto qo=encct(r,qr.first),ro=encct(r,qr.second);if(*ql<qo.size()||*rl<ro.size()){*ql=maximum;*rl=maximum;throw std::length_error("buffer too small");}memcpy(q,qo.data(),qo.size());memcpy(rem,ro.data(),ro.size());*ql=qo.size();*rl=ro.size();});if(r&&r->error=="buffer too small")return SOCI_BUFFER_TOO_SMALL;return s;}
#else
return disabled(r);
#endif
}
soci_status_t soci_start_cp_service(soci_runtime_t*r){return run(r,[&]{r->cp_running=true;});} soci_status_t soci_stop_cp_service(soci_runtime_t*r){return run(r,[&]{r->cp_running=false;});}
soci_status_t soci_start_csp_service(soci_runtime_t*r){return run(r,[&]{r->csp_running=true;});} soci_status_t soci_stop_csp_service(soci_runtime_t*r){return run(r,[&]{r->csp_running=false;});}
soci_status_t soci_health_check(soci_runtime_t*r){return run(r,[&]{});}
}
