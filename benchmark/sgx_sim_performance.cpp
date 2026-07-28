#include <sgx_urts.h>
#include "soci_u.h"
#include <gmpxx.h>
#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <numeric>
#include <random>
#include <vector>
using Clock=std::chrono::steady_clock;
#ifndef SOCI_SGX_BENCHMARK_MODE
#define SOCI_SGX_BENCHMARK_MODE "UNKNOWN"
#endif
static uint32_t get32(const uint8_t*p){return(uint32_t(p[0])<<24)|(uint32_t(p[1])<<16)|(uint32_t(p[2])<<8)|p[3];}
static void put32(uint8_t*p,uint32_t x){p[0]=x>>24;p[1]=x>>16;p[2]=x>>8;p[3]=x;}
struct Stats{double mean,p50,p95,min,max;};
static Stats stats(std::vector<double>v){std::sort(v.begin(),v.end());auto q=[&](double p){return v[std::min(v.size()-1,size_t(std::ceil(p*v.size()))-1)];};return{std::accumulate(v.begin(),v.end(),0.0)/v.size(),q(.5),q(.95),v.front(),v.back()};}
static void print(const char*n,const Stats&s,int samples){std::cout<<"    {\"operation\":\""<<n<<"\",\"samples\":"<<samples<<",\"mean_ms\":"<<s.mean<<",\"p50_ms\":"<<s.p50<<",\"p95_ms\":"<<s.p95<<",\"min_ms\":"<<s.min<<",\"max_ms\":"<<s.max<<",\"correct\":true}";}
int main(int argc,char**argv){
  if(argc<2){std::cerr<<"usage: sgx-benchmark ENCLAVE [decrypt_samples] [keygen_samples] [decrypt_warmup] [keygen_warmup]\n";return 2;}
  int ds=argc>2?std::stoi(argv[2]):100,ksamples=argc>3?std::stoi(argv[3]):30,
      dwarm=argc>4?std::stoi(argv[4]):10,kwarm=argc>5?std::stoi(argv[5]):5;
  if(ds<1||ksamples<1||dwarm<0||kwarm<0){std::cerr<<"invalid sample configuration\n";return 2;}
  sgx_enclave_id_t eid=0;sgx_launch_token_t token={0};int updated=0;
  if(sgx_create_enclave(argv[1],SGX_DEBUG_FLAG,&token,&updated,&eid,nullptr)!=SGX_SUCCESS){std::cerr<<"create enclave failed\n";return 1;}
  const char* mode=SOCI_SGX_BENCHMARK_MODE;
  uint8_t mode_id=std::strcmp(mode,"SIM")==0?1:
                  std::strcmp(mode,"HW")==0?2:0;
  if(mode_id==0){std::cerr<<"benchmark requires SIM or HW build mode\n";return 2;}
  uint8_t init[8]={'S','O','C','I',1,mode_id,0,0};uint32_t rv=99;
  if(ecall_initialize(eid,&rv,init,sizeof init)!=SGX_SUCCESS||rv){std::cerr<<"initialize failed\n";return 1;}
  uint8_t req[12]={'S','K','G','N',1,mode_id,0,0,0,0,12,0};std::vector<uint8_t>keyout(1024*1024);size_t out_size=0;std::vector<double>kg;
  auto keygen=[&](){auto s=ecall_keygen(eid,&rv,req,sizeof req,keyout.data(),keyout.size(),&out_size);if(s!=SGX_SUCCESS||rv){std::cerr<<"keygen failed sgx="<<std::hex<<s<<" app="<<rv<<"\n";return false;}return true;};
  for(int i=0;i<kwarm;i++)if(!keygen())return 1;
  for(int i=0;i<ksamples;i++){auto a=Clock::now();if(!keygen())return 1;auto b=Clock::now();kg.push_back(std::chrono::duration<double,std::milli>(b-a).count());}
  if(out_size<20||memcmp(keyout.data(),"SKGO",4)){std::cerr<<"bad key output\n";return 1;}uint32_t nlen=get32(keyout.data()+12),sealed_len=get32(keyout.data()+16);mpz_class n;mpz_import(n.get_mpz_t(),nlen,1,1,1,0,keyout.data()+20);mpz_class nsq=n*n,g=n+1,m=123456789,r=7;
  while(gcd(r,n)!=1)++r;mpz_class rn,gm,c;mpz_powm(rn.get_mpz_t(),r.get_mpz_t(),n.get_mpz_t(),nsq.get_mpz_t());gm=1+m*n;c=(gm*rn)%nsq;
  size_t clen=(mpz_sizeinbase(c.get_mpz_t(),2)+7)/8;std::vector<uint8_t>din(12+clen);memcpy(din.data(),"SDEC",4);din[4]=1;din[5]=mode_id;din[6]=0;din[7]=0;put32(din.data()+8,clen);size_t wrote=0;mpz_export(din.data()+12,&wrote,1,1,1,0,c.get_mpz_t());
  std::vector<uint8_t>plain(4096);std::vector<double>dec;
  auto decrypt=[&](){auto s=ecall_decrypt(eid,&rv,din.data(),din.size(),plain.data(),plain.size(),&out_size);if(s!=SGX_SUCCESS||rv){std::cerr<<"decrypt failed\n";return false;}return true;};
  for(int i=0;i<dwarm;i++)if(!decrypt())return 1;
  for(int i=0;i<ds;i++){auto a=Clock::now();if(!decrypt())return 1;auto b=Clock::now();dec.push_back(std::chrono::duration<double,std::milli>(b-a).count());}
  uint32_t mlen=get32(plain.data()+8);mpz_class actual;mpz_import(actual.get_mpz_t(),mlen,1,1,1,0,plain.data()+12);if(actual!=m){std::cerr<<"wrong plaintext\n";return 1;}
  ecall_close(eid,&rv);if(ecall_initialize(eid,&rv,init,sizeof init)!=SGX_SUCCESS||rv)return 1;
  if(ecall_load_sealed_key(eid,&rv,keyout.data()+20+nlen,sealed_len)!=SGX_SUCCESS||rv){std::cerr<<"unseal failed\n";return 1;}
  if(ecall_decrypt(eid,&rv,din.data(),din.size(),plain.data(),plain.size(),&out_size)!=SGX_SUCCESS||rv){std::cerr<<"decrypt after unseal failed\n";return 1;}
  ecall_close(eid,&rv);sgx_destroy_enclave(eid);auto ks=stats(kg),d=stats(dec);
  std::cout<<std::fixed<<std::setprecision(6)<<"{\n  \"mode\":\""<<mode<<"\",\n  \"modulus_bits\":3072,\n  \"bigint_backend\":\"GMP 6.2.1 static x86_64 assembly (k8 baseline)\",\n  \"enclave\":\""<<argv[1]<<"\",\n  \"timing_scope\":\"host steady_clock wall time including ECALL transition\",\n  \"warmup\":{\"keygen\":"<<kwarm<<",\"decrypt\":"<<dwarm<<"},\n  \"results\":[\n";print("ENCLAVE_KEYGEN_SEAL_EXPORT",ks,ksamples);std::cout<<",\n";print("ENCLAVE_FULL_DECRYPT",d,ds);std::cout<<"\n  ]\n}\n";
}
