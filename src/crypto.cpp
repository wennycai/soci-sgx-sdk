#include "internal.hpp"
#include <stdexcept>
#include <random>
namespace soci::detail {
static mpz_class lcmz(const mpz_class&a,const mpz_class&b){ mpz_class r; mpz_lcm(r.get_mpz_t(),a.get_mpz_t(),b.get_mpz_t()); return r; }
static mpz_class prime(gmp_randclass&r,uint32_t bits){ mpz_class p; do { p=r.get_z_bits(bits); mpz_setbit(p.get_mpz_t(),bits-1); mpz_setbit(p.get_mpz_t(),0); mpz_nextprime(p.get_mpz_t(),p.get_mpz_t()); } while(mpz_sizeinbase(p.get_mpz_t(),2)!=bits); return p; }
void keygen(uint32_t bits, Key& k) {
  if(bits<SOCI_SECURITY_128_MODULUS_BITS || bits>8192 || bits%2)
    throw std::invalid_argument("128-bit security profile requires an even modulus size in [3072,8192]");
  gmp_randclass r(gmp_randinit_default); mpz_class seed; std::random_device d; for(int i=0;i<8;i++){seed<<=32;seed+=d();} r.seed(seed);
  mpz_class p=prime(r,bits/2),q; do q=prime(r,bits/2); while(q==p);
  k.pub.n=p*q; k.pub.nsq=k.pub.n*k.pub.n; k.sec.lambda=lcmz(p-1,q-1);
  mpz_class u,g=k.pub.n+1; mpz_powm(u.get_mpz_t(),g.get_mpz_t(),k.sec.lambda.get_mpz_t(),k.pub.nsq.get_mpz_t());
  mpz_class l=(u-1)/k.pub.n; if(!mpz_invert(k.sec.mu.get_mpz_t(),l.get_mpz_t(),k.pub.n.get_mpz_t())) throw std::runtime_error("mu inverse failed");
  p=0;q=0;l=0;u=0;
}
mpz_class encrypt(const PublicKey&k,const mpz_class&m0,gmp_randclass&r) {
  mpz_class m=m0%k.n;if(m<0)m+=k.n;mpz_class x; do x=r.get_z_range(k.n); while(x==0 || gcd(x,k.n)!=1);
  mpz_class rn;mpz_powm(rn.get_mpz_t(),x.get_mpz_t(),k.n.get_mpz_t(),k.nsq.get_mpz_t()); return ((1+m*k.n)*rn)%k.nsq;
}
mpz_class decrypt(const Key&k,const mpz_class&c) {
  if(c<=0||c>=k.pub.nsq||gcd(c,k.pub.nsq)!=1)throw std::invalid_argument("invalid ciphertext");
  mpz_class u;mpz_powm(u.get_mpz_t(),c.get_mpz_t(),k.sec.lambda.get_mpz_t(),k.pub.nsq.get_mpz_t());
  mpz_class m=(((u-1)/k.pub.n)*k.sec.mu)%k.pub.n;if(m>=k.pub.n/2)m-=k.pub.n;return m;
}
}
