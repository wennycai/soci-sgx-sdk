#include "soci/soci.hpp"
#include <algorithm>
#include <chrono>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <functional>
#include <numeric>
#include <vector>
using Clock=std::chrono::steady_clock;
struct Stats{double mean,p50,p95,min,max;};
static Stats stats(std::vector<double> v){std::sort(v.begin(),v.end());double sum=std::accumulate(v.begin(),v.end(),0.0);auto q=[&](double p){return v[std::min(v.size()-1,size_t(p*(v.size()-1)))];};return{sum/v.size(),q(.5),q(.95),v.front(),v.back()};}
template<class F> static Stats measure(int n,F f){std::vector<double>v;v.reserve(n);for(int i=0;i<n;i++){auto a=Clock::now();f();auto b=Clock::now();v.push_back(std::chrono::duration<double,std::milli>(b-a).count());}return stats(v);}
static std::vector<uint8_t> out1(soci_runtime_t*r,const std::function<soci_status_t(uint8_t*,size_t*)>&f){size_t n=0;auto s=f(nullptr,&n);if(s!=SOCI_BUFFER_TOO_SMALL)throw soci::Error(soci_runtime_get_last_error(r));for(int i=0;i<3;i++){std::vector<uint8_t>o(n);s=f(o.data(),&n);if(s==SOCI_OK){o.resize(n);return o;}if(s!=SOCI_BUFFER_TOO_SMALL)throw soci::Error(soci_runtime_get_last_error(r));}throw soci::Error("output size unstable");}
static void row(const char*n,const Stats&s,int samples,bool ok){std::cout<<"    {\"operation\":\""<<n<<"\",\"samples\":"<<samples<<",\"mean_ms\":"<<s.mean<<",\"p50_ms\":"<<s.p50<<",\"p95_ms\":"<<s.p95<<",\"min_ms\":"<<s.min<<",\"max_ms\":"<<s.max<<",\"correct\":"<<(ok?"true":"false")<<"}";}
int main(int argc,char**argv){
  int bits=argc>1?std::stoi(argv[1]):SOCI_SECURITY_128_MODULUS_BITS,n=argc>2?std::stoi(argv[2]):20;
  auto root=std::filesystem::temp_directory_path()/"soci-performance";std::filesystem::remove_all(root);
  soci::Runtime r(root.string());std::cerr<<"benchmark: KEYGEN\n";auto kg=measure(3,[&]{static int x=0;r.create_key("bench"+std::to_string(x++),bits);});
  auto x=r.encrypt("120"),y=r.encrypt("7"),neg=r.encrypt("-120");bool enok=true,deok=true,mulok=true,cmpok=true,absok=true,divok=true;std::vector<uint8_t> z;
  std::cerr<<"benchmark: ENCRYPT\n";
  auto en=measure(n,[&]{z=r.encrypt("123456789");});enok=r.decrypt(z)=="123456789";
  std::cerr<<"benchmark: DECRYPT\n";
  auto de=measure(n,[&]{auto p=r.decrypt(x);if(p!="120")deok=false;});
  std::cerr<<"benchmark: SMUL\n";
  auto mul=measure(n,[&]{z=out1(r.native(),[&](uint8_t*o,size_t*l){return soci_secure_mul(r.native(),x.data(),x.size(),y.data(),y.size(),o,l);});});{auto actual=r.decrypt(z);mulok=actual=="840";if(!mulok)std::cerr<<"SMUL expected 840, got "<<actual<<"\n";}
  std::cerr<<"benchmark: SCMP\n";
  auto cmp=measure(n,[&]{z=out1(r.native(),[&](uint8_t*o,size_t*l){return soci_secure_compare(r.native(),x.data(),x.size(),y.data(),y.size(),o,l);});});cmpok=r.decrypt(z)=="1";
  std::cerr<<"benchmark: SABS\n";
  auto abs=measure(n,[&]{z=out1(r.native(),[&](uint8_t*o,size_t*l){return soci_secure_abs(r.native(),neg.data(),neg.size(),o,l);});});absok=r.decrypt(z)=="120";
  std::cerr<<"benchmark: SDIV\n";
  auto div=measure(n,[&]{size_t qn=0,rn=0;auto s=soci_secure_div(r.native(),x.data(),x.size(),y.data(),y.size(),nullptr,&qn,nullptr,&rn);if(s!=SOCI_BUFFER_TOO_SMALL)throw soci::Error(soci_runtime_get_last_error(r.native()));for(int retry=0;retry<3;retry++){std::vector<uint8_t>q(qn),rr(rn);s=soci_secure_div(r.native(),x.data(),x.size(),y.data(),y.size(),q.data(),&qn,rr.data(),&rn);if(s==SOCI_OK){q.resize(qn);rr.resize(rn);divok&=r.decrypt(q)=="17"&&r.decrypt(rr)=="1";break;}if(s!=SOCI_BUFFER_TOO_SMALL)throw soci::Error(soci_runtime_get_last_error(r.native()));}});
  std::cout<<std::fixed<<std::setprecision(6)<<"{\n  \"mode\":\""<<(r.mode()==SOCI_MODE_OFF?"OFF":r.mode()==SOCI_MODE_SIM?"SIM":"HW")<<"\",\n  \"modulus_bits\":"<<bits<<",\n  \"note\":\"experimental secure operations use decrypt-compute-encrypt and are OFF reference-only\",\n  \"results\":[\n";
  row("KEYGEN",kg,3,true);std::cout<<",\n";row("ENCRYPT",en,n,enok);std::cout<<",\n";row("DECRYPT",de,n,deok);std::cout<<",\n";row("SMUL",mul,n,mulok);std::cout<<",\n";row("SCMP",cmp,n,cmpok);std::cout<<",\n";row("SABS",abs,n,absok);std::cout<<",\n";row("SDIV",div,n,divok);std::cout<<"\n  ]\n}\n";return enok&&deok&&mulok&&cmpok&&absok&&divok?0:1;
}
