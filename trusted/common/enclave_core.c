#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <sgx_trts.h>
#include <sgx_tseal.h>
#include <gmp.h>

/*
 * GMP's allocation/assertion failure objects reference host stdio and signal
 * symbols. They must never OCALL from a secret-bearing failure path. Resolve
 * them inside the enclave and fail closed instead.
 */
void *stderr = NULL;
size_t fwrite(const void *ptr,size_t size,size_t count,void *stream)
{ (void)ptr;(void)size;(void)count;(void)stream;abort(); }
int __fprintf_chk(void *stream,int flag,const char *format,...)
{ (void)stream;(void)flag;(void)format;abort(); }
int raise(int sig) { (void)sig;abort(); }

#ifndef SOCI_ENCLAVE_ROLE
#define SOCI_ENCLAVE_ROLE 0
#endif
enum { OK=0, INVALID=1, STATE=2, CRYPTO=5, BUFFER=7 };
#define MAX_INPUT (1024u * 1024u)
bool initialized=false, keyed=false;
uint8_t runtime_mode=0, role=0;
mpz_t n, nsq, lambda_z, mu;
bool mpz_ready=false;

uint32_t be32(const uint8_t*p){return((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3];}
void put32(uint8_t*p,uint32_t x){p[0]=x>>24;p[1]=x>>16;p[2]=x>>8;p[3]=x;}
bool header(const uint8_t*p,size_t s,const char magic[4]){return p&&s>=8&&s<=MAX_INPUT&&!memcmp(p,magic,4)&&p[4]==1&&p[5]==runtime_mode;}
void wipe(mpz_t z){if(z->_mp_d&&z->_mp_alloc>0)memset(z->_mp_d,0,(size_t)z->_mp_alloc*sizeof(mp_limb_t));mpz_clear(z);}
void clear_key(){if(!mpz_ready)return;wipe(n);wipe(nsq);wipe(lambda_z);wipe(mu);mpz_ready=false;keyed=false;}
bool random_odd(mpz_t z,uint32_t bits){
  const size_t bytes=(bits+7)/8;uint8_t*buf=(uint8_t*)malloc(bytes);if(!buf)return false;
  if(sgx_read_rand(buf,bytes)!=SGX_SUCCESS){memset(buf,0,bytes);free(buf);return false;}
  buf[0]|=0x80;buf[bytes-1]|=1;mpz_import(z,bytes,1,1,1,0,buf);memset(buf,0,bytes);free(buf);return true;
}
bool prime(mpz_t p,uint32_t bits){if(!random_odd(p,bits))return false;while(mpz_sizeinbase(p,2)==bits){if(mpz_probab_prime_p(p,32)>0)return true;mpz_add_ui(p,p,2);}return prime(p,bits);}
bool random_below(mpz_t z,const mpz_t limit){
  size_t bytes=(mpz_sizeinbase(limit,2)+7)/8;uint8_t*buf=(uint8_t*)malloc(bytes);if(!buf)return false;
  if(sgx_read_rand(buf,bytes)!=SGX_SUCCESS){memset(buf,0,bytes);free(buf);return false;}
  mpz_import(z,bytes,1,1,1,0,buf);mpz_mod(z,z,limit);memset(buf,0,bytes);free(buf);
  if(mpz_cmp_ui(z,0)==0)mpz_set_ui(z,1);return true;
}
size_t exported_size(const mpz_t z){return(mpz_sizeinbase(z,2)+7)/8;}
bool export_at(uint8_t*out,size_t cap,size_t*pos,const mpz_t z){
  size_t len=exported_size(z);if(*pos+4+len>cap)return false;put32(out+*pos,len);*pos+=4;
  size_t wrote=0;mpz_export(out+*pos,&wrote,1,1,1,0,z);*pos+=wrote;return wrote==len;
}
bool import_at(mpz_t z,const uint8_t*in,size_t size,size_t*pos){
  if(*pos+4>size)return false;uint32_t len=be32(in+*pos);*pos+=4;if(!len||*pos+len>size)return false;
  mpz_import(z,len,1,1,1,0,in+*pos);*pos+=len;return true;
}

bool seal_share(uint8_t share_role,const mpz_t share,const mpz_t combiner,
                uint32_t bits,uint8_t*out,uint32_t out_len){
  size_t plain_cap=20+exported_size(n)+exported_size(share)+
                   (share_role==2?exported_size(combiner)+4:0);
  uint8_t*plain=(uint8_t*)malloc(plain_cap);if(!plain)return false;
  memcpy(plain,"TSHR",4);plain[4]=1;plain[5]=runtime_mode;plain[6]=share_role;plain[7]=0;
  put32(plain+8,bits);size_t pos=12;
  bool good=export_at(plain,plain_cap,&pos,n)&&export_at(plain,plain_cap,&pos,share);
  if(good&&share_role==2)good=export_at(plain,plain_cap,&pos,combiner);
  sgx_attributes_t mask={0xfffffffffffffff3ULL,0};
  sgx_status_t status=good?sgx_seal_data_ex(SGX_KEYPOLICY_MRSIGNER,mask,0,0,NULL,
    (uint32_t)pos,plain,out_len,(sgx_sealed_data_t*)out):SGX_ERROR_UNEXPECTED;
  memset(plain,0,plain_cap);free(plain);return status==SGX_SUCCESS;
}

uint32_t ecall_initialize(uint8_t* p,size_t s){
  if(!p||s!=8||memcmp(p,"SOCI",4)||p[4]!=1||p[5]<1||p[5]>2||p[6]!=SOCI_ENCLAVE_ROLE)return INVALID;
  clear_key();runtime_mode=p[5];role=p[6];initialized=true;return OK;
}
uint32_t ecall_keygen(uint8_t*in,size_t in_size,uint8_t*out,size_t cap,size_t*out_size){
  if(!initialized||SOCI_ENCLAVE_ROLE!=0)return STATE;if(!out_size||!header(in,in_size,"SKGN")||in_size!=12)return INVALID;
  uint32_t bits=be32(in+8);if(bits<3072||bits>8192||(bits&1))return INVALID;
  clear_key();mpz_init(n);mpz_init(nsq);mpz_init(lambda_z);mpz_init(mu);mpz_ready=true;
  mpz_t p,q,p1,q1,g,u,l;mpz_init(p);mpz_init(q);mpz_init(p1);mpz_init(q1);mpz_init(g);mpz_init(u);mpz_init(l);
  bool good=prime(p,bits/2);do{good=good&&prime(q,bits/2);}while(good&&mpz_cmp(p,q)==0);
  if(good){mpz_mul(n,p,q);mpz_mul(nsq,n,n);mpz_sub_ui(p1,p,1);mpz_sub_ui(q1,q,1);mpz_lcm(lambda_z,p1,q1);
    mpz_add_ui(g,n,1);mpz_powm(u,g,lambda_z,nsq);mpz_sub_ui(l,u,1);mpz_fdiv_q(l,l,n);good=mpz_invert(mu,l,n)!=0;}
  wipe(p);wipe(q);wipe(p1);wipe(q1);wipe(g);wipe(u);wipe(l);if(!good){clear_key();return CRYPTO;}
  size_t secret_cap=24+exported_size(n)+exported_size(lambda_z)+exported_size(mu);
  uint8_t*secret=(uint8_t*)malloc(secret_cap);if(!secret){clear_key();return CRYPTO;}size_t sp=0;
  memcpy(secret,"SKEY",4);secret[4]=1;secret[5]=runtime_mode;secret[6]=role;secret[7]=0;sp=8;put32(secret+sp,bits);sp+=4;
  good=export_at(secret,secret_cap,&sp,n)&&export_at(secret,secret_cap,&sp,lambda_z)&&export_at(secret,secret_cap,&sp,mu);
  uint32_t sealed_len=good?sgx_calc_sealed_data_size(0,(uint32_t)sp):UINT32_MAX;
  if(sealed_len==UINT32_MAX){memset(secret,0,secret_cap);free(secret);clear_key();return CRYPTO;}
  size_t nlen=exported_size(n),required=20+nlen+sealed_len;*out_size=required;
  if(!out||cap<required){memset(secret,0,secret_cap);free(secret);return BUFFER;}
  memcpy(out,"SKGO",4);out[4]=1;out[5]=runtime_mode;out[6]=role;out[7]=0;put32(out+8,bits);put32(out+12,nlen);put32(out+16,sealed_len);
  size_t wrote=0;mpz_export(out+20,&wrote,1,1,1,0,n);
  sgx_status_t ss=sgx_seal_data(0,NULL,(uint32_t)sp,secret,sealed_len,(sgx_sealed_data_t*)(out+20+nlen));
  memset(secret,0,secret_cap);free(secret);keyed=ss==SGX_SUCCESS;return keyed?OK:CRYPTO;
}
uint32_t ecall_threshold_keygen(uint8_t*in,size_t in_size,uint8_t*out,size_t cap,size_t*out_size){
  if(!initialized||SOCI_ENCLAVE_ROLE!=0)return STATE;
  if(!out_size||!header(in,in_size,"SKGN")||in_size!=12)return INVALID;
  uint32_t bits=be32(in+8);if(bits<3072||bits>8192||(bits&1))return INVALID;
  clear_key();mpz_init(n);mpz_init(nsq);mpz_init(lambda_z);mpz_init(mu);mpz_ready=true;
  mpz_t p,q,p1,q1,g,u,l,lambda1,lambda2;
  mpz_init(p);mpz_init(q);mpz_init(p1);mpz_init(q1);mpz_init(g);mpz_init(u);mpz_init(l);
  mpz_init(lambda1);mpz_init(lambda2);
  bool good=prime(p,bits/2);do{good=good&&prime(q,bits/2);}while(good&&mpz_cmp(p,q)==0);
  if(good){mpz_mul(n,p,q);mpz_mul(nsq,n,n);mpz_sub_ui(p1,p,1);mpz_sub_ui(q1,q,1);
    mpz_lcm(lambda_z,p1,q1);mpz_add_ui(g,n,1);mpz_powm(u,g,lambda_z,nsq);
    mpz_sub_ui(l,u,1);mpz_fdiv_q(l,l,n);good=mpz_invert(mu,l,n)!=0;}
  if(good)good=random_below(lambda1,lambda_z);
  if(good){mpz_sub(lambda2,lambda_z,lambda1);good=mpz_cmp_ui(lambda2,0)>0;}
  size_t cp_plain=20+exported_size(n)+exported_size(lambda1);
  size_t csp_plain=24+exported_size(n)+exported_size(lambda2)+exported_size(mu);
  uint32_t cp_len=good?sgx_calc_sealed_data_size(0,(uint32_t)cp_plain):UINT32_MAX;
  uint32_t csp_len=good?sgx_calc_sealed_data_size(0,(uint32_t)csp_plain):UINT32_MAX;
  size_t nlen=good?exported_size(n):0,required=24+nlen+cp_len+csp_len;
  if(!good||cp_len==UINT32_MAX||csp_len==UINT32_MAX){required=0;}
  if(required)*out_size=required;
  if(!required){good=false;}
  else if(!out||cap<required){good=false;required=BUFFER;}
  else{
    memcpy(out,"STKO",4);out[4]=1;out[5]=runtime_mode;out[6]=0;out[7]=0;
    put32(out+8,bits);put32(out+12,(uint32_t)nlen);put32(out+16,cp_len);put32(out+20,csp_len);
    size_t wrote=0;mpz_export(out+24,&wrote,1,1,1,0,n);
    good=wrote==nlen&&seal_share(1,lambda1,mu,bits,out+24+nlen,cp_len)&&
      seal_share(2,lambda2,mu,bits,out+24+nlen+cp_len,csp_len);
  }
  wipe(p);wipe(q);wipe(p1);wipe(q1);wipe(g);wipe(u);wipe(l);wipe(lambda1);wipe(lambda2);
  if(required==BUFFER)return BUFFER;if(!good){clear_key();return CRYPTO;}keyed=true;return OK;
}
uint32_t ecall_decrypt(uint8_t*in,size_t in_size,uint8_t*out,size_t cap,size_t*out_size){
  if(!initialized||!keyed)return STATE;if(!out_size||!header(in,in_size,"SDEC")||in_size<12)return INVALID;
  uint8_t decrypt_mode=in[6];if(decrypt_mode!=0)return INVALID;size_t pos=8;mpz_t c,u,m;mpz_init(c);mpz_init(u);mpz_init(m);
  bool good=import_at(c,in,in_size,&pos)&&pos==in_size&&mpz_cmp_ui(c,0)>0&&mpz_cmp(c,nsq)<0;
  if(good){mpz_powm(u,c,lambda_z,nsq);mpz_sub_ui(u,u,1);mpz_fdiv_q(u,u,n);mpz_mul(m,u,mu);mpz_mod(m,m,n);}
  size_t len=good?exported_size(m):0,required=12+len;*out_size=required;
  if(!good){wipe(c);wipe(u);wipe(m);return INVALID;}if(!out||cap<required){wipe(c);wipe(u);wipe(m);return BUFFER;}
  memcpy(out,"SPLN",4);out[4]=1;out[5]=runtime_mode;out[6]=0;out[7]=0;put32(out+8,len);size_t wrote=0;mpz_export(out+12,&wrote,1,1,1,0,m);
  wipe(c);wipe(u);wipe(m);return wrote==len?OK:CRYPTO;
}
uint32_t ecall_partial_decrypt(uint8_t*in,size_t in_size,uint8_t*out,size_t cap,size_t*out_size){
  if(!initialized||!keyed||(role!=1&&role!=2))return STATE;
  if(!out_size||!header(in,in_size,"SPDC")||in_size<12)return INVALID;
  size_t pos=8;mpz_t c,u;mpz_init(c);mpz_init(u);
  bool good=import_at(c,in,in_size,&pos)&&pos==in_size&&mpz_cmp_ui(c,0)>0&&mpz_cmp(c,nsq)<0;
  if(good)mpz_powm(u,c,lambda_z,nsq);
  size_t len=good?exported_size(u):0,required=12+len;*out_size=required;
  if(!good){wipe(c);wipe(u);return INVALID;}if(!out||cap<required){wipe(c);wipe(u);return BUFFER;}
  memcpy(out,"SPAR",4);out[4]=1;out[5]=runtime_mode;out[6]=role;out[7]=0;put32(out+8,(uint32_t)len);
  size_t wrote=0;mpz_export(out+12,&wrote,1,1,1,0,u);wipe(c);wipe(u);return wrote==len?OK:CRYPTO;
}
uint32_t ecall_combine_decrypt(uint8_t*in,size_t in_size,uint8_t*out,size_t cap,size_t*out_size){
  if(!initialized||!keyed||role!=2)return STATE;
  if(!out_size||!header(in,in_size,"SCMB")||in_size<16)return INVALID;
  size_t pos=8;mpz_t u1,u2,u,m;mpz_init(u1);mpz_init(u2);mpz_init(u);mpz_init(m);
  bool good=import_at(u1,in,in_size,&pos)&&import_at(u2,in,in_size,&pos)&&pos==in_size;
  if(good){mpz_mul(u,u1,u2);mpz_mod(u,u,nsq);mpz_sub_ui(u,u,1);
    good=mpz_divisible_p(u,n)!=0;if(good){mpz_fdiv_q(u,u,n);mpz_mul(m,u,mu);mpz_mod(m,m,n);}}
  size_t len=good?exported_size(m):0,required=12+len;*out_size=required;
  if(!good){wipe(u1);wipe(u2);wipe(u);wipe(m);return INVALID;}
  if(!out||cap<required){wipe(u1);wipe(u2);wipe(u);wipe(m);return BUFFER;}
  memcpy(out,"SPLN",4);out[4]=1;out[5]=runtime_mode;out[6]=3;out[7]=0;put32(out+8,(uint32_t)len);
  size_t wrote=0;mpz_export(out+12,&wrote,1,1,1,0,m);
  wipe(u1);wipe(u2);wipe(u);wipe(m);return wrote==len?OK:CRYPTO;
}
uint32_t ecall_load_sealed_key(uint8_t*in,size_t size){
  if(!initialized||!in||size<sizeof(sgx_sealed_data_t)||size>MAX_INPUT)return INVALID;
  sgx_sealed_data_t*sealed=(sgx_sealed_data_t*)in;uint32_t plain_len=sgx_get_encrypt_txt_len(sealed);if(plain_len<24||plain_len>MAX_INPUT)return INVALID;
  uint8_t*p=(uint8_t*)malloc(plain_len);if(!p)return CRYPTO;uint32_t actual=plain_len;
  sgx_status_t s=sgx_unseal_data(sealed,NULL,NULL,p,&actual);
  bool threshold=actual>=20&&!memcmp(p,"TSHR",4);
  bool full=actual>=24&&!memcmp(p,"SKEY",4);
  if(s!=SGX_SUCCESS||actual!=plain_len||(!threshold&&!full)||p[4]!=1||p[5]!=runtime_mode||p[6]!=role){memset(p,0,plain_len);free(p);return INVALID;}
  clear_key();mpz_init(n);mpz_init(nsq);mpz_init(lambda_z);mpz_init(mu);mpz_ready=true;size_t pos=12;
  bool good=import_at(n,p,plain_len,&pos)&&import_at(lambda_z,p,plain_len,&pos);
  if(good&&(!threshold||role==2))good=import_at(mu,p,plain_len,&pos);else mpz_set_ui(mu,0);
  good=good&&pos==plain_len;
  if(good)mpz_mul(nsq,n,n);memset(p,0,plain_len);free(p);keyed=good;if(!good)clear_key();return good?OK:INVALID;
}
uint32_t ecall_get_public_key(uint8_t*out,size_t cap,size_t*out_size){
  if(!keyed)return STATE;if(!out_size)return INVALID;size_t len=exported_size(n),required=12+len;*out_size=required;if(!out||cap<required)return BUFFER;
  memcpy(out,"SPUB",4);out[4]=1;out[5]=runtime_mode;out[6]=role;out[7]=0;put32(out+8,len);size_t wrote=0;mpz_export(out+12,&wrote,1,1,1,0,n);return wrote==len?OK:CRYPTO;
}
uint32_t ecall_get_key_info(uint8_t*out,size_t cap,size_t*out_size){if(!keyed)return STATE;if(!out_size)return INVALID;*out_size=12;if(!out||cap<12)return BUFFER;memcpy(out,"SINF",4);out[4]=1;out[5]=runtime_mode;out[6]=role;out[7]=0;put32(out+8,mpz_sizeinbase(n,2));return OK;}
uint32_t ecall_close(){clear_key();initialized=false;runtime_mode=role=0;return OK;}
