#include "internal.hpp"
#include "ciphertext_codec.hpp"
#include <openssl/sha.h>
#include <fstream>
#include <cstring>
#include <cctype>
#include <stdexcept>
namespace soci::detail {
static void put32(std::vector<uint8_t>&o,uint32_t x){for(int i=3;i>=0;i--)o.push_back(uint8_t(x>>(i*8)));}
static uint32_t get32(const uint8_t*p){return(uint32_t(p[0])<<24)|(uint32_t(p[1])<<16)|(uint32_t(p[2])<<8)|p[3];}
static std::vector<uint8_t> mag(const mpz_class&z){size_t n=(mpz_sizeinbase(z.get_mpz_t(),2)+7)/8;std::vector<uint8_t>o(n);if(n)mpz_export(o.data(),nullptr,1,1,1,0,z.get_mpz_t());return o;}
static mpz_class unmag(const uint8_t*p,size_t n){mpz_class z;if(n)mpz_import(z.get_mpz_t(),n,1,1,1,0,p);return z;}
std::vector<uint8_t> encode_object(uint8_t type,soci_mode_t mode,const mpz_class&z){if(type==1)return encodeCanonicalCiphertext(uint8_t(mode),z);auto m=mag(z);std::vector<uint8_t>o{'S','O','C','I',1,type,uint8_t(mode),0};put32(o,m.size());o.insert(o.end(),m.begin(),m.end());return o;}
mpz_class decode_object(const uint8_t*p,size_t n,uint8_t type,soci_mode_t mode){if(n>kMaxObject)throw std::invalid_argument("object too large");if(type==1)return decodeCanonicalCiphertext(p,n,uint8_t(mode));if(!p||n<12||memcmp(p,"SOCI",4)||p[4]!=1||p[5]!=type||p[6]!=mode)throw std::invalid_argument("invalid object header/type/mode");uint32_t s=get32(p+8);if(s!=n-12)throw std::invalid_argument("invalid object length");return unmag(p+12,s);}
std::vector<uint8_t> encode_public(const Key&k){return encode_object(2,k.info.runtime_mode,k.pub.n);}
bool valid_id(const std::string&s){if(s.empty()||s.size()>64)return false;for(char c:s)if(!isalnum((unsigned char)c)&&c!='-'&&c!='_')return false;return true;}
void save_off_key(const std::filesystem::path&p,const Key&k){
  std::vector<uint8_t>o{'S','O','C','K',1,uint8_t(k.info.runtime_mode),uint8_t(k.info.role),0};put32(o,k.info.modulus_bits);
  for(int i=7;i>=0;i--)o.push_back(uint8_t(k.info.key_version>>(i*8)));auto id=std::string(k.info.key_id);put32(o,id.size());o.insert(o.end(),id.begin(),id.end());
  for(auto*z:{&k.pub.n,&k.sec.lambda,&k.sec.mu}){auto m=mag(*z);put32(o,m.size());o.insert(o.end(),m.begin(),m.end());}
  unsigned char h[SHA256_DIGEST_LENGTH];SHA256(o.data(),o.size(),h);o.insert(o.end(),h,h+sizeof h);
  std::filesystem::create_directories(p.parent_path());auto tmp=p;tmp+=".tmp";std::ofstream f(tmp,std::ios::binary|std::ios::trunc);f.write((char*)o.data(),o.size());f.close();std::filesystem::permissions(tmp,std::filesystem::perms::owner_read|std::filesystem::perms::owner_write);std::filesystem::rename(tmp,p);
}
Key load_off_key(const std::filesystem::path&p,soci_mode_t mode,soci_role_t role){
  std::ifstream f(p,std::ios::binary);std::vector<uint8_t>o((std::istreambuf_iterator<char>(f)),{});if(o.size()<56||o.size()>kMaxObject)throw std::runtime_error("missing/truncated key blob");
  unsigned char h[32];SHA256(o.data(),o.size()-32,h);if(memcmp(h,o.data()+o.size()-32,32))throw std::runtime_error("key blob integrity failure");
  if(memcmp(o.data(),"SOCK",4)||o[4]!=1||o[5]!=mode||o[6]!=role)throw std::runtime_error("key format/mode/role mismatch");size_t x=8;Key k{};k.info.struct_version=1;k.info.runtime_mode=mode;k.info.role=role;k.info.modulus_bits=get32(o.data()+x);x+=4;k.info.key_version=0;for(int i=0;i<8;i++)k.info.key_version=(k.info.key_version<<8)|o[x++];
  auto take=[&](){if(x+4>o.size()-32)throw std::runtime_error("truncated key");uint32_t n=get32(o.data()+x);x+=4;if(x+n>o.size()-32)throw std::runtime_error("truncated key");auto z=unmag(o.data()+x,n);x+=n;return z;};
  uint32_t il=get32(o.data()+x);x+=4;if(il>64||x+il>o.size()-32)throw std::runtime_error("bad key id");memcpy(k.info.key_id,o.data()+x,il);k.info.key_id[il]=0;x+=il;k.pub.n=take();k.pub.nsq=k.pub.n*k.pub.n;k.sec.lambda=take();k.sec.mu=take();if(x!=o.size()-32)throw std::runtime_error("trailing key data");return k;
}
}
