#include <sgx_urts.h>
#include "soci_u.h"
#include <gmpxx.h>
#include <arpa/inet.h>
#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <netdb.h>
#include <netinet/in.h>
#include <random>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

using Bytes=std::vector<uint8_t>;
using Clock=std::chrono::steady_clock;
static uint8_t wire_mode(){const char*m=getenv("SOCI_SGX_MODE");return m&&std::string(m)=="SIM"?1:2;}
static const char* mode_name(){return wire_mode()==1?"SIM":"HW";}
static uint32_t be32(const uint8_t*p){return(uint32_t(p[0])<<24)|(uint32_t(p[1])<<16)|(uint32_t(p[2])<<8)|p[3];}
static void put32(uint8_t*p,uint32_t x){p[0]=x>>24;p[1]=x>>16;p[2]=x>>8;p[3]=x;}
static void append(Bytes&o,const mpz_class&z){size_t n=(mpz_sizeinbase(z.get_mpz_t(),2)+7)/8,p=o.size();o.resize(p+4+n);put32(o.data()+p,n);size_t w=0;mpz_export(o.data()+p+4,&w,1,1,1,0,z.get_mpz_t());}
static mpz_class take(const Bytes&b,size_t&p){if(p+4>b.size())throw std::runtime_error("short integer");uint32_t n=be32(b.data()+p);p+=4;if(!n||p+n>b.size())throw std::runtime_error("bad integer");mpz_class z;mpz_import(z.get_mpz_t(),n,1,1,1,0,b.data()+p);p+=n;return z;}
static Bytes file(const std::string&p){std::ifstream f(p,std::ios::binary);if(!f)throw std::runtime_error("cannot read "+p);return Bytes(std::istreambuf_iterator<char>(f),{});}
static void save(const std::string&p,const uint8_t*d,size_t n){std::ofstream f(p,std::ios::binary|std::ios::trunc);if(!f||!f.write((const char*)d,n))throw std::runtime_error("cannot write "+p);}
static void exact(int fd,void*p,size_t n,bool wr){auto*q=(uint8_t*)p;while(n){ssize_t k=wr?send(fd,q,n,MSG_NOSIGNAL):recv(fd,q,n,0);if(k<=0)throw std::runtime_error("socket closed");q+=k;n-=k;}}
static void frame(int fd,const Bytes&b){uint8_t h[4];put32(h,b.size());exact(fd,h,4,true);if(!b.empty())exact(fd,(void*)b.data(),b.size(),true);}
static Bytes frame(int fd){uint8_t h[4];exact(fd,h,4,false);uint32_t n=be32(h);if(n>4*1024*1024)throw std::runtime_error("frame too large");Bytes b(n);if(n)exact(fd,b.data(),n,false);return b;}
static sgx_enclave_id_t enclave(const std::string&p){sgx_enclave_id_t e=0;sgx_launch_token_t t={};int u=0;auto s=sgx_create_enclave(p.c_str(),SGX_DEBUG_FLAG,&t,&u,&e,nullptr);if(s!=SGX_SUCCESS)throw std::runtime_error("sgx_create_enclave failed: "+std::to_string(s));return e;}
static void init(sgx_enclave_id_t e,uint8_t role){uint8_t q[8]={'S','O','C','I',1,wire_mode(),role,0};uint32_t rv;if(ecall_initialize(e,&rv,q,8)!=SGX_SUCCESS||rv)throw std::runtime_error("initialize failed");}
static mpz_class response(const Bytes&b,const char*m){if(b.size()<12||memcmp(b.data(),m,4)||12u+be32(b.data()+8)!=b.size())throw std::runtime_error("bad enclave response");size_t p=8;return take(b,p);}
static mpz_class partial(sgx_enclave_id_t e,const mpz_class&c,double*us=nullptr){Bytes q={'S','P','D','C',1,wire_mode(),0,0};append(q,c);Bytes o(16384);size_t n=0;uint32_t rv;auto a=Clock::now();auto s=ecall_partial_decrypt(e,&rv,q.data(),q.size(),o.data(),o.size(),&n);auto z=Clock::now();if(us)*us+=std::chrono::duration<double,std::micro>(z-a).count();if(s!=SGX_SUCCESS||rv)throw std::runtime_error("partial decrypt failed");o.resize(n);return response(o,"SPAR");}
static mpz_class combine(sgx_enclave_id_t e,const mpz_class&a,const mpz_class&b){Bytes q={'S','C','M','B',1,wire_mode(),0,0};append(q,a);append(q,b);Bytes o(8192);size_t n=0;uint32_t rv;if(ecall_combine_decrypt(e,&rv,q.data(),q.size(),o.data(),o.size(),&n)!=SGX_SUCCESS||rv)throw std::runtime_error("combine failed");o.resize(n);return response(o,"SPLN");}
static gmp_randclass rng(gmp_randinit_default);
static mpz_class enc(const mpz_class&m,const mpz_class&n){mpz_class ns=n*n,r,c,rn;do r=rng.get_z_range(n);while(r==0||gcd(r,n)!=1);mpz_powm(rn.get_mpz_t(),r.get_mpz_t(),n.get_mpz_t(),ns.get_mpz_t());return ((1+(m%n+n)%n*n)*rn)%ns;}
static mpz_class signed_m(const mpz_class&m,const mpz_class&n){return m>n/2?m-n:m;}
static mpz_class add_ct(const mpz_class&a,const mpz_class&b,const mpz_class&ns){return a*b%ns;}
static mpz_class pow_ct(const mpz_class&c,const mpz_class&k,const mpz_class&ns){
  mpz_class base=c,exponent=k,out;
  if(exponent<0){mpz_class inverse;if(!mpz_invert(inverse.get_mpz_t(),base.get_mpz_t(),ns.get_mpz_t()))throw std::runtime_error("ciphertext inverse failed");base=std::move(inverse);exponent=-exponent;}
  mpz_powm(out.get_mpz_t(),base.get_mpz_t(),exponent.get_mpz_t(),ns.get_mpz_t());return out;
}
static int connect_to(const std::string&host,int port){
  const std::string service=std::to_string(port);
  for(int i=0;i<60;i++){
    addrinfo hints{},*list=nullptr;hints.ai_family=AF_INET;hints.ai_socktype=SOCK_STREAM;
    if(getaddrinfo(host.c_str(),service.c_str(),&hints,&list)==0){
      for(addrinfo*p=list;p;p=p->ai_next){int fd=socket(p->ai_family,p->ai_socktype,p->ai_protocol);
        if(fd>=0&&connect(fd,p->ai_addr,p->ai_addrlen)==0){freeaddrinfo(list);return fd;}
        if(fd>=0)close(fd);}
      freeaddrinfo(list);
    }
    usleep(250000);
  }
  throw std::runtime_error("connect CSP failed: "+host+":"+service);
}
static Bytes request(int fd,char op,const std::vector<mpz_class>&v,double*us=nullptr){Bytes q{uint8_t(op)};for(auto&z:v)append(q,z);auto a=Clock::now();frame(fd,q);Bytes r=frame(fd);auto b=Clock::now();if(us)*us+=std::chrono::duration<double,std::micro>(b-a).count();if(r.empty()||r[0])throw std::runtime_error("CSP request failed");return Bytes(r.begin()+1,r.end());}

static int provision(const char*ep,const char*dir,unsigned bits){
  auto e=enclave(ep);init(e,0);uint8_t q[12]={'S','K','G','N',1,wire_mode(),0,0,0,0,0,0};put32(q+8,bits);
  Bytes o(3*1024*1024);size_t n=0;uint32_t rv;auto a=Clock::now();
  auto s=ecall_threshold_keygen(e,&rv,q,12,o.data(),o.size(),&n);double ms=std::chrono::duration<double,std::milli>(Clock::now()-a).count();
  if(s!=SGX_SUCCESS||rv||n<24||memcmp(o.data(),"STKO",4))throw std::runtime_error("threshold keygen failed");
  uint32_t nl=be32(o.data()+12),cl=be32(o.data()+16),sl=be32(o.data()+20);if(24ull+nl+cl+sl!=n)throw std::runtime_error("bad key package");
  std::string d=dir;save(d+"/public.bin",o.data()+24,nl);save(d+"/cp.sealed",o.data()+24+nl,cl);save(d+"/csp.sealed",o.data()+24+nl+cl,sl);
  std::cout<<"{\"mode\":\""<<mode_name()<<"\",\"role\":\"Provisioning\",\"operation\":\"KeyGen\",\"security_bits\":128,\"modulus_bits\":"<<bits<<",\"milliseconds\":"<<ms<<"}\n";
  sgx_destroy_enclave(e);return 0;
}
static mpz_class load_n(const std::string&p){Bytes b=file(p);mpz_class n;mpz_import(n.get_mpz_t(),b.size(),1,1,1,0,b.data());return n;}
static void load_share(sgx_enclave_id_t e,const std::string&p){Bytes b=file(p);uint32_t rv;if(ecall_load_sealed_key(e,&rv,b.data(),b.size())!=SGX_SUCCESS||rv)throw std::runtime_error("sealed share rejected");}

static int csp(const char*ep,const char*dir,int port){
  auto e=enclave(ep);init(e,2);load_share(e,std::string(dir)+"/csp.sealed");mpz_class n=load_n(std::string(dir)+"/public.bin");
  int ls=socket(AF_INET,SOCK_STREAM,0),one=1;setsockopt(ls,SOL_SOCKET,SO_REUSEADDR,&one,sizeof(one));sockaddr_in a{};a.sin_family=AF_INET;a.sin_addr.s_addr=INADDR_ANY;a.sin_port=htons(port);
  if(bind(ls,(sockaddr*)&a,sizeof(a))||listen(ls,8))throw std::runtime_error("listen failed");
  std::cerr<<"CSP ready on "<<port<<"\n";
  for(;;){int fd=accept(ls,nullptr,nullptr);if(fd<0)continue;try{for(;;){Bytes q=frame(fd);if(q.empty())throw std::runtime_error("empty");char op=q[0];size_t p=1;std::vector<mpz_class> z;while(p<q.size())z.push_back(take(q,p));Bytes r{0};
      if(op=='Q'){frame(fd,r);close(fd);close(ls);sgx_destroy_enclave(e);std::cerr<<"CSP stopped after CP completion\n";return 0;}
      if(op=='D'&&z.size()==2){append(r,combine(e,z[1],partial(e,z[0])));}
      else if(op=='M'&&z.size()==3){
        // SOCI-plus SMUL packs X=x+r1 and Y=y+r2 as C=X^L*Y, so CSP performs
        // one threshold decryption and sees only the two masked operands.
        const mpz_class&packed=z[0];const mpz_class&packing_base=z[2];
        if(packing_base<=1)throw std::runtime_error("invalid SMUL packing base");
        mpz_class plaintext=combine(e,z[1],partial(e,packed));
        mpz_class x1=plaintext/packing_base,y1=plaintext%packing_base;
        append(r,enc(x1*y1,n));
      }
      else if(op=='C'&&z.size()==2){
        // SOCI-plus SCMP: D is a randomized, randomly-oriented difference.
        // CSP learns only which half of Z_N contains d, never x, y or the
        // orientation bit selected by CP.
        mpz_class d=combine(e,z[1],partial(e,z[0]));
        append(r,enc(d>n/2?0:1,n));
      }
      else r[0]=1;frame(fd,r);}}
      catch(const std::exception&error){std::cerr<<"CSP request rejected: "<<error.what()<<"\n";close(fd);}
      catch(...){std::cerr<<"CSP request rejected: unknown error\n";close(fd);}}
}
struct Samples{std::string name,security;std::vector<double> total,cp,net;bool ok=true;};
static double pct(std::vector<double>v,double p){std::sort(v.begin(),v.end());return v[std::min(v.size()-1,size_t(std::ceil(p*v.size())-1))];}
static void json(const Samples&s){double sum=0;for(double x:s.total)sum+=x;std::cout<<"    {\"operation\":\""<<s.name<<"\",\"security\":\""<<s.security<<"\",\"samples\":"<<s.total.size()<<",\"mean_us\":"<<sum/s.total.size()<<",\"p50_us\":"<<pct(s.total,.5)<<",\"p95_us\":"<<pct(s.total,.95)<<",\"cp_enclave_mean_us\":";sum=0;for(double x:s.cp)sum+=x;std::cout<<(s.cp.empty()?0:sum/s.cp.size())<<",\"csp_roundtrip_mean_us\":";sum=0;for(double x:s.net)sum+=x;std::cout<<(s.net.empty()?0:sum/s.net.size())<<",\"correct\":"<<(s.ok?"true":"false")<<"}";}
static int benchmark(const char*ep,const char*dir,const std::string&host,int port,int warm,int count){
  auto e=enclave(ep);init(e,1);load_share(e,std::string(dir)+"/cp.sealed");mpz_class n=load_n(std::string(dir)+"/public.bin"),ns=n*n;
  int fd=connect_to(host,port);rng.seed(std::random_device{}());std::vector<Samples> all;
  auto run=[&](std::string name,std::string sec,auto fn){std::cerr<<"CP benchmark "<<name<<" (warmup="<<warm<<", samples="<<count<<")\n";Samples s{name,sec};for(int i=-warm;i<count;i++){double cp=0,net=0;auto a=Clock::now();bool ok=fn(cp,net);double us=std::chrono::duration<double,std::micro>(Clock::now()-a).count();if(i>=0){s.total.push_back(us);s.cp.push_back(cp);s.net.push_back(net);s.ok&=ok;}}std::cerr<<"CP benchmark "<<name<<" complete\n";all.push_back(std::move(s));};
  // Keep the high bit set: protocol operands are range-bounded, so masked
  // values stay positive and below the 130-bit packing base.
  auto random128=[&](){return (mpz_class(1)<<127)+rng.get_z_bits(127);};
  auto smul=[&](const mpz_class&ax,const mpz_class&ay,double&cp,double&net){
    mpz_class r1=random128(),r2=random128();
    mpz_class X=add_ct(ax,enc(r1,n),ns),Y=add_ct(ay,enc(r2,n),ns);
    // SOCI-plus uses C = X^L * Y.  L=2^130 safely separates the benchmark's
    // bounded operands after adding 128-bit masks.
    mpz_class packing_base=mpz_class(1)<<130;
    mpz_class packed=add_ct(pow_ct(X,packing_base,ns),Y,ns);
    Bytes reply=request(fd,'M',{packed,partial(e,packed,&cp),packing_base},&net);size_t p=0;
    mpz_class product=take(reply,p);
    product=add_ct(product,pow_ct(ax,-r2,ns),ns);
    product=add_ct(product,pow_ct(ay,-r1,ns),ns);
    product=add_ct(product,enc(-r1*r2,n),ns);
    return product;
  };
  // SOCI-plus primitive Enc(ax < ay). The public SCMP convention is recovered
  // as slt(ay, ax), i.e. Enc(ax > ay), matching soci_secure_compare.
  auto slt=[&](const mpz_class&ax,const mpz_class&ay,double&cp,double&net){
    mpz_class r3=random128(),r;
    do r=random128();while(r>=r3);
    mpz_class r4=n/2-r,difference;bool pi=(rng.get_z_bits(1)!=0);
    if(!pi){
      difference=add_ct(ax,pow_ct(ay,n-1,ns),ns);
      difference=add_ct(pow_ct(difference,r3,ns),enc(r3+r4,n),ns);
    }else{
      difference=add_ct(ay,pow_ct(ax,-1,ns),ns);
      difference=add_ct(pow_ct(difference,r3,ns),enc(r4,n),ns);
    }
    if(difference<=0||difference>=ns||gcd(difference,n)!=1)throw std::runtime_error("SCMP produced invalid ciphertext");
    Bytes reply=request(fd,'C',{difference,partial(e,difference,&cp)},&net);size_t p=0;
    mpz_class bit=take(reply,p);
    return pi?add_ct(enc(1,n),pow_ct(bit,-1,ns),ns):bit; // Enc(x < y)
  };
  auto sabs=[&](const mpz_class&ax,double&cp,double&net){
    mpz_class sign=slt(ax,enc(0,n),cp,net);
    mpz_class factor=add_ct(enc(1,n),pow_ct(sign,-2,ns),ns);
    return smul(factor,ax,cp,net);
  };
  auto sdiv=[&](mpz_class dividend,const mpz_class&divisor,unsigned bits,double&cp,double&net){
    mpz_class quotient=enc(0,n),one=enc(1,n);
    for(unsigned step=bits;step-->0;){
      mpz_class shifted=pow_ct(divisor,mpz_class(1)<<step,ns);
      mpz_class less=slt(dividend,shifted,cp,net);        // Enc(x < y*2^step)
      mpz_class take_bit=add_ct(one,pow_ct(less,-1,ns),ns); // Enc(1-less)
      quotient=add_ct(quotient,pow_ct(take_bit,mpz_class(1)<<step,ns),ns);
      mpz_class subtraction=smul(take_bit,shifted,cp,net);
      dividend=add_ct(dividend,pow_ct(subtraction,-1,ns),ns);
    }
    return std::make_pair(quotient,dividend);
  };
  mpz_class x=12345,y=67,cx=enc(x,n),cy=enc(y,n);
  auto reveal=[&](const mpz_class&z,double&cp,double&net){Bytes d=request(fd,'D',{z,partial(e,z,&cp)},&net);size_t p=0;return signed_m(take(d,p),n);};
  run("Encrypt","public", [&](double&,double&){return enc(x,n)>0;});
  run("SADD","public", [&](double&,double&){return cx*cy%ns>0;});
  run("ScalarMul","public", [&](double&,double&){mpz_class z;mpz_powm_ui(z.get_mpz_t(),cx.get_mpz_t(),19,ns.get_mpz_t());return z>0;});
  run("Decrypt","threshold", [&](double&cp,double&net){mpz_class u=partial(e,cx,&cp);Bytes r=request(fd,'D',{cx,u},&net);size_t p=0;return signed_m(take(r,p),n)==x;});
  run("SMUL","soci-plus-masked-threshold", [&](double&cp,double&net){return reveal(smul(cx,cy,cp,net),cp,net)==x*y;});
  run("SCMP","soci-plus-masked-threshold", [&](double&cp,double&net){
    mpz_class greater=slt(cy,cx,cp,net),equal=slt(cx,cx,cp,net);
    return reveal(greater,cp,net)==1&&reveal(equal,cp,net)==0;
  });
  run("SABS","soci-plus-composed", [&](double&cp,double&net){mpz_class negative=enc(-x,n);return reveal(sabs(negative,cp,net),cp,net)==x;});
  run("SDIV","soci-plus-composed", [&](double&cp,double&net){auto qr=sdiv(cx,cy,16,cp,net);return reveal(qr.first,cp,net)==x/y&&reveal(qr.second,cp,net)==x%y;});
  std::cout<<"{\n  \"mode\":\""<<mode_name()<<"\",\"architecture\":\"CP/CSP dual process\",\"security_bits\":128,\"modulus_bits\":"<<mpz_sizeinbase(n.get_mpz_t(),2)<<",\"warmup\":"<<warm<<",\"metrics\":[\n";
  for(size_t i=0;i<all.size();i++){json(all[i]);std::cout<<(i+1==all.size()?"\n":",\n");}std::cout<<"  ]\n}\n";
  request(fd,'Q',{});
  close(fd);sgx_destroy_enclave(e);return 0;
}
int main(int argc,char**argv){try{
  if(argc>=4&&std::string(argv[1])=="provision")return provision(argv[2],argv[3],argc>4?std::stoul(argv[4]):3072);
  if(argc>=5&&std::string(argv[1])=="csp")return csp(argv[2],argv[3],std::stoi(argv[4]));
  if(argc>=7&&std::string(argv[1])=="benchmark")return benchmark(argv[2],argv[3],argv[4],std::stoi(argv[5]),std::stoi(argv[6]),argc>7?std::stoi(argv[7]):30);
  std::cerr<<"usage: soci_threshold_runtime provision ENCLAVE DIR [BITS] | csp ENCLAVE DIR PORT | benchmark ENCLAVE DIR HOST PORT WARMUP [SAMPLES]\n";return 2;
 }catch(const std::exception&e){std::cerr<<e.what()<<"\n";return 1;}}
