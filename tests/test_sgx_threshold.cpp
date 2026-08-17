#include <sgx_urts.h>
#include "soci_u.h"
#include "soci/threshold_limits.h"
#include <gmpxx.h>
#include <array>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <vector>

static uint32_t get32(const uint8_t* p) {
  return (uint32_t(p[0])<<24)|(uint32_t(p[1])<<16)|(uint32_t(p[2])<<8)|p[3];
}
static void put32(uint8_t* p,uint32_t x) {
  p[0]=x>>24;p[1]=x>>16;p[2]=x>>8;p[3]=x;
}
static void append_mpz(std::vector<uint8_t>& out,const mpz_class& value) {
  size_t len=(mpz_sizeinbase(value.get_mpz_t(),2)+7)/8,pos=out.size();
  out.resize(pos+4+len);put32(out.data()+pos,uint32_t(len));size_t wrote=0;
  mpz_export(out.data()+pos+4,&wrote,1,1,1,0,value.get_mpz_t());
  if(wrote!=len)throw std::runtime_error("mpz export failed");
}
static mpz_class parse_value(const std::vector<uint8_t>& in,const char magic[4]) {
  if(in.size()<12||std::memcmp(in.data(),magic,4))throw std::runtime_error("bad response");
  uint32_t len=get32(in.data()+8);if(12u+len!=in.size())throw std::runtime_error("bad length");
  mpz_class value;mpz_import(value.get_mpz_t(),len,1,1,1,0,in.data()+12);return value;
}
static sgx_enclave_id_t create(const char* path) {
  sgx_enclave_id_t eid=0;sgx_launch_token_t token={};int updated=0;
  auto status=sgx_create_enclave(path,SGX_DEBUG_FLAG,&token,&updated,&eid,nullptr);
  if(status!=SGX_SUCCESS)throw std::runtime_error("sgx_create_enclave failed");
  return eid;
}
static void initialize(sgx_enclave_id_t eid,uint8_t mode,uint8_t role) {
  std::array<uint8_t,8> request{{'S','O','C','I',1,mode,role,0}};uint32_t rv=99;
  if(ecall_initialize(eid,&rv,request.data(),request.size())!=SGX_SUCCESS||rv)
    throw std::runtime_error("initialize failed");
}
int main(int argc,char** argv) {
  if(argc!=5){std::cerr<<"usage: threshold-test PROVISIONING CP CSP MODE\n";return 2;}
  uint8_t mode=std::string(argv[4])=="SIM"?1:2;
  sgx_enclave_id_t provisioning=0,cp=0,csp=0;
  try {
    provisioning=create(argv[1]);cp=create(argv[2]);csp=create(argv[3]);
    initialize(provisioning,mode,0);initialize(cp,mode,1);initialize(csp,mode,2);
    std::array<uint8_t,12> request{{'S','K','G','N',1,mode,0,0,0,0,12,0}};
    std::vector<uint8_t> package(3*1024*1024);size_t package_size=0;uint32_t rv=99;
    auto status=ecall_threshold_keygen(provisioning,&rv,request.data(),request.size(),
      package.data(),package.size(),&package_size);
    if(status!=SGX_SUCCESS||rv||package_size<24||std::memcmp(package.data(),"STKO",4))
      throw std::runtime_error("threshold keygen failed");
    package.resize(package_size);
    uint32_t nlen=get32(package.data()+12),cp_len=get32(package.data()+16),
             csp_len=get32(package.data()+20);
    if(24ull+nlen+cp_len+csp_len!=package.size())throw std::runtime_error("bad package");
    uint8_t* nbytes=package.data()+24;
    uint8_t* cp_blob=nbytes+nlen;uint8_t* csp_blob=cp_blob+cp_len;
    if(ecall_load_sealed_key(cp,&rv,cp_blob,cp_len)!=SGX_SUCCESS||rv)
      throw std::runtime_error("CP share load failed");
    if(ecall_load_sealed_key(csp,&rv,csp_blob,csp_len)!=SGX_SUCCESS||rv)
      throw std::runtime_error("CSP share load failed");
    mpz_class n;mpz_import(n.get_mpz_t(),nlen,1,1,1,0,nbytes);
    mpz_class nsq=n*n,m=123456789,r=7,rn,c;
    while(gcd(r,n)!=1)++r;
    mpz_powm(rn.get_mpz_t(),r.get_mpz_t(),n.get_mpz_t(),nsq.get_mpz_t());
    c=((1+m*n)*rn)%nsq;
    std::vector<uint8_t> partial_req{'S','P','D','C',1,mode,0,0};append_mpz(partial_req,c);
    auto partial=[&](sgx_enclave_id_t eid) {
      std::vector<uint8_t> out(8192);size_t size=0;
      if(ecall_partial_decrypt(eid,&rv,partial_req.data(),partial_req.size(),
          out.data(),out.size(),&size)!=SGX_SUCCESS||rv)throw std::runtime_error("partial failed");
      out.resize(size);return parse_value(out,"SPAR");
    };
    mpz_class u1=partial(cp),u2=partial(csp);
    std::vector<uint8_t> combine{'S','C','M','B',1,mode,0,0};
    append_mpz(combine,u1);append_mpz(combine,u2);
    std::vector<uint8_t> plain(4096);size_t plain_size=0;
    if(ecall_combine_decrypt(csp,&rv,combine.data(),combine.size(),plain.data(),
        plain.size(),&plain_size)!=SGX_SUCCESS||rv)throw std::runtime_error("combine failed");
    plain.resize(plain_size);
    if(parse_value(plain,"SPLN")!=m)throw std::runtime_error("wrong plaintext");
    auto batch_request=[&](uint32_t count) {
      std::vector<uint8_t> value{'S','T','D','B',1,mode,0,0,0,0,0,0};
      put32(value.data()+8,count);
      for(uint32_t i=0;i<count;i++){append_mpz(value,c);append_mpz(value,u1);}
      return value;
    };
    auto require_batch_ok=[&](uint32_t count) {
      auto input=batch_request(count);std::vector<uint8_t> output(512*1024);size_t size=0;rv=99;
      if(ecall_threshold_decrypt_batch(csp,&rv,input.data(),input.size(),output.data(),output.size(),&size)!=SGX_SUCCESS||rv)
        throw std::runtime_error("valid threshold batch rejected");
      output.resize(size);if(output.size()<12||std::memcmp(output.data(),"STDR",4)||get32(output.data()+8)!=count)
        throw std::runtime_error("bad threshold batch response");
      size_t offset=12;for(uint32_t i=0;i<count;i++){if(offset+4>output.size())throw std::runtime_error("short threshold batch response");uint32_t len=get32(output.data()+offset);offset+=4;if(!len||len>output.size()-offset)throw std::runtime_error("bad threshold batch item");mpz_class got;mpz_import(got.get_mpz_t(),len,1,1,1,0,output.data()+offset);offset+=len;if(got!=m)throw std::runtime_error("wrong threshold batch plaintext");}if(offset!=output.size())throw std::runtime_error("trailing threshold batch response");
    };
    auto require_batch_bad=[&](std::vector<uint8_t> input) {
      std::vector<uint8_t> output(512*1024);size_t size=0;rv=0;
      const auto call=ecall_threshold_decrypt_batch(csp,&rv,input.data(),input.size(),output.data(),output.size(),&size);
      if(call!=SGX_SUCCESS||rv==0||size!=0)
        throw std::runtime_error("malformed threshold batch did not fail closed");
    };
    require_batch_ok(1);require_batch_ok(SOCI_THRESHOLD_MAX_BATCH_SIZE);
    require_batch_bad(batch_request(SOCI_THRESHOLD_MAX_BATCH_SIZE+1));
    auto wrong_count=batch_request(1);put32(wrong_count.data()+8,2);require_batch_bad(std::move(wrong_count));
    auto truncated=batch_request(1);truncated.pop_back();require_batch_bad(std::move(truncated));
    auto trailing=batch_request(1);trailing.push_back(0);require_batch_bad(std::move(trailing));
    std::cout<<"SGX "<<argv[4]<<" threshold provisioning and CP/CSP decrypt passed\n";
    sgx_destroy_enclave(provisioning);sgx_destroy_enclave(cp);sgx_destroy_enclave(csp);return 0;
  } catch(const std::exception& e) {
    std::cerr<<e.what()<<"\n";
    if(provisioning)sgx_destroy_enclave(provisioning);
    if(cp)sgx_destroy_enclave(cp);if(csp)sgx_destroy_enclave(csp);return 1;
  }
}
