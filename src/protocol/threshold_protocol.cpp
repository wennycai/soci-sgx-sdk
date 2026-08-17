#include "protocol/threshold_protocol.hpp"

#include "ciphertext_codec.hpp"
#include "protocol/threshold_wire.hpp"
#include "soci_u.h"

#include <arpa/inet.h>
#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <cstdlib>
#include <iostream>
#include <mutex>
#include <netinet/in.h>
#include <optional>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <sgx_urts.h>
#include <stdexcept>
#include <sys/socket.h>
#include <sys/random.h>
#include <thread>
#include <unordered_set>
#include <unistd.h>
#include <utility>
#include <vector>

namespace soci::protocol {
namespace {
using Clock = std::chrono::steady_clock;
using wire::Bytes;
mpz_class randomBits(unsigned bits);
mpz_class randomBelow(const mpz_class& limit);

struct BooleanGate { std::uint32_t left, right, output; };
struct BooleanCircuit {
  std::uint32_t input_count{};
  std::vector<BooleanGate> and_gates;
  // Each wire is represented as an XOR of source wires plus a public constant.
  struct LinearWire { std::vector<std::uint32_t> terms; bool constant{}; };
  std::vector<LinearWire> wires;
  std::uint32_t output{};
};

BooleanCircuit predicateCircuit(secure::PredicateType type,
                                std::uint32_t comparisons,
                                bool has_incumbent) {
  BooleanCircuit c; c.input_count=comparisons;c.wires.reserve(comparisons+comparisons);
  for(std::uint32_t i=0;i<comparisons;++i)c.wires.push_back({{i},false});
  const auto linear=[&](std::vector<std::uint32_t> terms,bool constant=false){
    c.wires.push_back({std::move(terms),constant});return static_cast<std::uint32_t>(c.wires.size()-1);};
  const auto land=[&](std::uint32_t a,std::uint32_t b){
    const auto out=linear({});c.and_gates.push_back({a,b,out});return out;};
  if(type==secure::PredicateType::prune_node){
    if(!has_incumbent){c.output=0;return c;}
    if(comparisons<2)throw std::invalid_argument("bad fused PRUNE comparison count");
    std::uint32_t folded=1;
    for(std::uint32_t i=2;i<comparisons;++i){const auto p=land(folded,i);folded=linear({folded,i,p});}
    const auto p=land(0,folded);c.output=linear({0,folded,p});return c;
  }
  if(type!=secure::PredicateType::accept_candidate||
     comparisons!=(has_incumbent?5u:2u))
    throw std::invalid_argument("bad fused ACCEPT comparison count");
  const auto linear_ge=linear({0},true);
  const auto feasible=land(linear_ge,1);
  if(!has_incumbent){c.output=feasible;return c;}
  const auto cost_eq=linear({2,3},true);
  const auto equal_c12=land(cost_eq,4);
  const auto better=linear({2,equal_c12});
  c.output=land(feasible,better);return c;
}

using Label=std::array<std::uint8_t,32>;
Label randomLabel(){Label x;if(RAND_bytes(x.data(),x.size())!=1)throw std::runtime_error("predicate RNG failed");return x;}
Label labelXor(const Label&a,const Label&b){Label x;for(std::size_t i=0;i<x.size();++i)x[i]=a[i]^b[i];return x;}
Label gatePad(const Label&a,const Label&b,std::uint32_t gate){
  SHA256_CTX s;Label out;SHA256_Init(&s);SHA256_Update(&s,a.data(),a.size());
  SHA256_Update(&s,b.data(),b.size());std::uint8_t id[4];wire::writeU32(id,gate);
  SHA256_Update(&s,id,sizeof(id));SHA256_Final(out.data(),&s);return out;
}
void appendLabel(Bytes&out,const Label&x){out.insert(out.end(),x.begin(),x.end());}
Label takeLabel(const Bytes&in,std::size_t&off){if(in.size()-off<32)throw std::runtime_error("short predicate label");Label x;std::copy_n(in.data()+off,32,x.data());off+=32;return x;}

struct GarbledPredicate {
  BooleanCircuit circuit;
  Label delta;
  std::vector<Label> zero;
  std::vector<std::array<Label,4>> tables;
};
GarbledPredicate garblePredicate(secure::PredicateType type,std::uint32_t count,
                                 bool has_incumbent){
  GarbledPredicate g;g.circuit=predicateCircuit(type,count,has_incumbent);
  g.delta=randomLabel();g.delta.back()|=1;g.zero.resize(g.circuit.wires.size());
  for(std::uint32_t i=0;i<count;++i)g.zero[i]=randomLabel();
  std::size_t gi=0;
  for(std::uint32_t w=count;w<g.circuit.wires.size();++w){
    const auto&lin=g.circuit.wires[w];
    if(!lin.terms.empty()){Label z{};for(auto t:lin.terms)z=labelXor(z,g.zero[t]);if(lin.constant)z=labelXor(z,g.delta);g.zero[w]=z;continue;}
    const auto&gate=g.circuit.and_gates.at(gi);g.zero[w]=randomLabel();std::array<Label,4> table;
    for(unsigned a=0;a<2;++a)for(unsigned b=0;b<2;++b){auto la=a?labelXor(g.zero[gate.left],g.delta):g.zero[gate.left];auto lb=b?labelXor(g.zero[gate.right],g.delta):g.zero[gate.right];auto pad=gatePad(la,lb,static_cast<std::uint32_t>(gi));auto target=(a&b)?labelXor(g.zero[w],g.delta):g.zero[w];table[((la.back()&1)<<1)|(lb.back()&1)]=labelXor(pad,target);}
    g.tables.push_back(table);++gi;
  }return g;
}
Label otPad(const mpz_class&key,std::uint32_t index){
  const auto n=(mpz_sizeinbase(key.get_mpz_t(),2)+7)/8;Bytes bytes(n? n:1);std::size_t wrote=0;
  mpz_export(bytes.data(),&wrote,1,1,1,0,key.get_mpz_t());SHA256_CTX s;Label out;
  SHA256_Init(&s);SHA256_Update(&s,bytes.data(),bytes.size());std::uint8_t id[4];wire::writeU32(id,index);
  SHA256_Update(&s,id,4);SHA256_Final(out.data(),&s);std::fill(bytes.begin(),bytes.end(),0);return out;
}
mpz_class randomBelowNonzero(const mpz_class&limit){mpz_class x;do{x=randomBelow(limit);}while(x==0);return x;}
mpz_class bnToMpz(const BIGNUM*bn){const auto size=BN_num_bytes(bn);Bytes b(size);BN_bn2bin(bn,b.data());mpz_class z;mpz_import(z.get_mpz_t(),b.size(),1,1,1,0,b.data());return z;}

std::uint8_t modeByte(ThresholdMode mode) {
  return static_cast<std::uint8_t>(mode);
}

sgx_enclave_id_t createEnclave(const std::string& path) {
  sgx_enclave_id_t enclave = 0;
  sgx_launch_token_t token{};
  int updated = 0;
  const auto status = sgx_create_enclave(path.c_str(), SGX_DEBUG_FLAG, &token,
                                         &updated, &enclave, nullptr);
  if (status != SGX_SUCCESS)
    throw std::runtime_error("sgx_create_enclave failed: " +
                             std::to_string(status));
  return enclave;
}

void initializeEnclave(sgx_enclave_id_t enclave, std::uint8_t role,
                       ThresholdMode mode) {
  std::uint8_t request[8] = {'S', 'O', 'C', 'I', 1, modeByte(mode), role, 0};
  std::uint32_t result = 0;
  if (ecall_initialize(enclave, &result, request, sizeof(request)) !=
          SGX_SUCCESS ||
      result != 0)
    throw std::runtime_error("initialize failed");
}

mpz_class parseEnclaveResponse(const Bytes& response, const char* magic) {
  if (response.size() < 12 || std::memcmp(response.data(), magic, 4) != 0 ||
      12u + wire::readU32(response.data() + 8) != response.size())
    throw std::runtime_error("bad enclave response");
  std::size_t offset = 8;
  return wire::takeInteger(response, offset);
}

mpz_class partialDecrypt(sgx_enclave_id_t enclave,
                         const mpz_class& ciphertext, ThresholdMode mode,
                         double* microseconds = nullptr) {
  Bytes request{'S', 'P', 'D', 'C', 1, modeByte(mode), 0, 0};
  wire::appendInteger(request, ciphertext);
  Bytes response(16384);
  std::size_t response_size = 0;
  std::uint32_t result = 0;
  const auto start = Clock::now();
  const auto status = ecall_partial_decrypt(
      enclave, &result, request.data(), request.size(), response.data(),
      response.size(), &response_size);
  if (microseconds)
    *microseconds +=
        std::chrono::duration<double, std::micro>(Clock::now() - start).count();
  if (status != SGX_SUCCESS || result != 0)
    throw std::runtime_error("partial decrypt failed");
  response.resize(response_size);
  return parseEnclaveResponse(response, "SPAR");
}

std::vector<mpz_class> partialDecryptBatch(
    sgx_enclave_id_t enclave, const std::vector<mpz_class>& ciphertexts,
    ThresholdMode mode, double* microseconds = nullptr) {
  if (ciphertexts.empty() ||
      ciphertexts.size() > SOCI_THRESHOLD_MAX_BATCH_SIZE)
    throw std::invalid_argument("invalid partial decrypt batch size");
  Bytes request{'S','P','D','B',1,modeByte(mode),0,0,0,0,0,0};
  wire::writeU32(request.data()+8, static_cast<std::uint32_t>(ciphertexts.size()));
  for (const auto& value : ciphertexts) wire::appendInteger(request, value);
  Bytes response(256 * 1024); std::size_t response_size=0; std::uint32_t result=0;
  const auto start=Clock::now();
  const auto status=ecall_partial_decrypt_batch(enclave,&result,request.data(),request.size(),response.data(),response.size(),&response_size);
  if (microseconds) *microseconds += std::chrono::duration<double,std::micro>(Clock::now()-start).count();
  if(status!=SGX_SUCCESS||result!=0) throw std::runtime_error("partial decrypt batch failed");
  response.resize(response_size);
  if(response.size()<12||std::memcmp(response.data(),"SPBR",4)||response[4]!=1||response[5]!=modeByte(mode)||response[7]!=0||wire::readU32(response.data()+8)!=ciphertexts.size())
    throw std::runtime_error("bad partial decrypt batch response");
  std::size_t offset=12;std::vector<mpz_class> output;output.reserve(ciphertexts.size());
  for(std::size_t i=0;i<ciphertexts.size();++i) output.push_back(wire::takeInteger(response,offset));
  if(offset!=response.size()) throw std::runtime_error("trailing partial decrypt batch data");
  return output;
}

std::vector<mpz_class> thresholdDecryptBatch(
    sgx_enclave_id_t enclave, const std::vector<mpz_class>& ciphertexts,
    const std::vector<mpz_class>& cp_shares, ThresholdMode mode) {
  if (ciphertexts.empty() || ciphertexts.size() != cp_shares.size() ||
      ciphertexts.size() > SOCI_THRESHOLD_MAX_BATCH_SIZE)
    throw std::invalid_argument("invalid threshold decrypt batch size");
  Bytes request{'S','T','D','B',1,modeByte(mode),0,0,0,0,0,0};
  wire::writeU32(request.data()+8,
                 static_cast<std::uint32_t>(ciphertexts.size()));
  for (std::size_t i=0;i<ciphertexts.size();++i) {
    wire::appendInteger(request,ciphertexts[i]);
    wire::appendInteger(request,cp_shares[i]);
  }
  Bytes response(512*1024);std::size_t response_size=0;std::uint32_t result=0;
  const auto status=ecall_threshold_decrypt_batch(
      enclave,&result,request.data(),request.size(),response.data(),
      response.size(),&response_size);
  if(status!=SGX_SUCCESS||result!=0)
    throw std::runtime_error("threshold decrypt batch failed");
  response.resize(response_size);
  if(response.size()<12||std::memcmp(response.data(),"STDR",4)||
     response[4]!=1||response[5]!=modeByte(mode)||response[6]!=3||
     response[7]!=0||wire::readU32(response.data()+8)!=ciphertexts.size())
    throw std::runtime_error("bad threshold decrypt batch response");
  std::size_t offset=12;std::vector<mpz_class> output;output.reserve(ciphertexts.size());
  for(std::size_t i=0;i<ciphertexts.size();++i)
    output.push_back(wire::takeInteger(response,offset));
  if(offset!=response.size())
    throw std::runtime_error("trailing threshold decrypt batch data");
  return output;
}

mpz_class combineDecrypt(sgx_enclave_id_t enclave, const mpz_class& cp_share,
                         const mpz_class& csp_share, ThresholdMode mode) {
  Bytes request{'S', 'C', 'M', 'B', 1, modeByte(mode), 0, 0};
  wire::appendInteger(request, cp_share);
  wire::appendInteger(request, csp_share);
  Bytes response(8192);
  std::size_t response_size = 0;
  std::uint32_t result = 0;
  const auto status = ecall_combine_decrypt(
      enclave, &result, request.data(), request.size(), response.data(),
      response.size(), &response_size);
  if (status != SGX_SUCCESS || result != 0)
    throw std::runtime_error("combine failed: sgx=" +
                             std::to_string(status) +
                             " result=" + std::to_string(result));
  response.resize(response_size);
  return parseEnclaveResponse(response, "SPLN");
}

mpz_class loadModulus(const std::string& path) {
  const auto bytes = wire::readFile(path);
  mpz_class modulus;
  mpz_import(modulus.get_mpz_t(), bytes.size(), 1, 1, 1, 0, bytes.data());
  return modulus;
}

void loadShare(sgx_enclave_id_t enclave, const std::string& path) {
  auto bytes = wire::readFile(path);
  std::uint32_t result = 0;
  if (ecall_load_sealed_key(enclave, &result, bytes.data(), bytes.size()) !=
          SGX_SUCCESS ||
      result != 0)
    throw std::runtime_error("sealed share rejected");
}

mpz_class ciphertextPower(const mpz_class& ciphertext,
                          const mpz_class& exponent,
                          const mpz_class& modulus_squared) {
  mpz_class base = ciphertext;
  mpz_class power = exponent;
  if (power < 0) {
    mpz_class inverse;
    if (!mpz_invert(inverse.get_mpz_t(), base.get_mpz_t(),
                    modulus_squared.get_mpz_t()))
      throw std::runtime_error("ciphertext inverse failed");
    base = std::move(inverse);
    power = -power;
  }
  mpz_class result;
  mpz_powm(result.get_mpz_t(), base.get_mpz_t(), power.get_mpz_t(),
           modulus_squared.get_mpz_t());
  return result;
}

mpz_class encodeCiphertext(const secure::Ciphertext& ciphertext,
                           ThresholdMode mode) {
  if (ciphertext.bytes.empty()) throw std::invalid_argument("empty ciphertext");
  return detail::decodeCanonicalCiphertext(ciphertext.bytes.data(),
                                           ciphertext.bytes.size(),
                                           modeByte(mode));
}

secure::Ciphertext decodeCiphertext(const mpz_class& value,
                                    ThresholdMode mode) {
  return {detail::encodeCanonicalCiphertext(modeByte(mode), value)};
}

mpz_class randomBits(unsigned bits) {
  if (bits == 0) return 0;
  std::vector<unsigned char> bytes((bits + 7) / 8);
  std::size_t offset = 0;
  while (offset < bytes.size()) {
    const auto count =
        getrandom(bytes.data() + offset, bytes.size() - offset, 0);
    if (count < 0) {
      if (errno == EINTR) continue;
      throw std::runtime_error("getrandom CSPRNG failure");
    }
    if (count == 0) throw std::runtime_error("getrandom returned no data");
    offset += static_cast<std::size_t>(count);
  }
  const unsigned excess = bytes.size() * 8 - bits;
  if (excess) bytes.front() &= static_cast<unsigned char>(0xffu >> excess);
  mpz_class value;
  mpz_import(value.get_mpz_t(), bytes.size(), 1, 1, 1, 0, bytes.data());
  return value;
}

mpz_class randomBelow(const mpz_class& limit) {
  if (limit <= 0) throw std::invalid_argument("random limit must be positive");
  const mpz_class maximum = limit - 1;
  const auto bits = mpz_sizeinbase(maximum.get_mpz_t(), 2);
  mpz_class value;
  do value = randomBits(bits);
  while (value >= limit);
  return value;
}

std::size_t encryptionThreadCount() {
  constexpr std::size_t default_threads=4;
  constexpr std::size_t maximum_threads=16;
  const char* configured=std::getenv("SOCI_THRESHOLD_ENCRYPT_THREADS");
  if(!configured||!*configured) return default_threads;
  char* end=nullptr;
  errno=0;
  const auto value=std::strtoul(configured,&end,10);
  if(errno||*end!='\0'||value==0||value>maximum_threads)
    throw std::runtime_error("SOCI_THRESHOLD_ENCRYPT_THREADS must be 1..16");
  return static_cast<std::size_t>(value);
}

mpz_class paillierEncrypt(const mpz_class& plaintext,const mpz_class& modulus,
                          const mpz_class& modulus_squared) {
  mpz_class nonce,nonce_n;
  do nonce=randomBelow(modulus);
  while(nonce==0||gcd(nonce,modulus)!=1);
  mpz_powm(nonce_n.get_mpz_t(),nonce.get_mpz_t(),modulus.get_mpz_t(),
           modulus_squared.get_mpz_t());
  mpz_class normalized=plaintext%modulus;
  if(normalized<0) normalized+=modulus;
  mpz_class message_factor=normalized*modulus+1;
  return message_factor*nonce_n%modulus_squared;
}

std::vector<mpz_class> paillierEncryptBatch(
    const std::vector<mpz_class>& plaintexts,const mpz_class& modulus,
    const mpz_class& modulus_squared,std::size_t configured_threads) {
  std::vector<mpz_class> output(plaintexts.size());
  if(plaintexts.empty()) return output;
  const auto threads=std::min(configured_threads,plaintexts.size());
  if(threads==1) {
    for(std::size_t i=0;i<plaintexts.size();++i)
      output[i]=paillierEncrypt(plaintexts[i],modulus,modulus_squared);
    return output;
  }
  std::atomic<std::size_t> next{0};
  std::exception_ptr failure;
  std::mutex failure_mutex;
  auto worker=[&] {
    try {
      for(;;) {
        const auto i=next.fetch_add(1,std::memory_order_relaxed);
        if(i>=plaintexts.size()) return;
        output[i]=paillierEncrypt(plaintexts[i],modulus,modulus_squared);
      }
    } catch(...) {
      std::lock_guard<std::mutex> lock(failure_mutex);
      if(!failure) failure=std::current_exception();
      next.store(plaintexts.size(),std::memory_order_relaxed);
    }
  };
  std::vector<std::thread> workers;
  workers.reserve(threads);
  for(std::size_t i=0;i<threads;++i) workers.emplace_back(worker);
  for(auto& worker_thread:workers) worker_thread.join();
  if(failure) std::rethrow_exception(failure);
  return output;
}

void appendContextString(Bytes& output, const std::string& value) {
  if (value.empty() || value.size() > 128)
    throw secure::PredicateError("invalid predicate context field");
  const auto offset = output.size();
  output.resize(offset + 4 + value.size());
  wire::writeU32(output.data() + offset,
                 static_cast<std::uint32_t>(value.size()));
  std::memcpy(output.data() + offset + 4, value.data(), value.size());
}

std::string takeContextString(const Bytes& input, std::size_t& offset) {
  if (offset + 4 > input.size())
    throw std::runtime_error("short predicate context");
  const auto size = wire::readU32(input.data() + offset);
  offset += 4;
  if (size == 0 || size > 128 || offset + size > input.size())
    throw std::runtime_error("invalid predicate context field");
  std::string value(reinterpret_cast<const char*>(input.data() + offset), size);
  offset += size;
  return value;
}

template <typename Integer>
std::uint32_t ceilLog2(Integer value) {
  if (value <= 1) return 0;
  --value;
  std::uint32_t bits = 0;
  while (value != 0) {
    value >>= 1;
    ++bits;
  }
  return bits;
}

std::uint32_t checkedBitSum(std::uint32_t left, std::uint32_t right,
                            const char* message) {
  if (right > UINT32_MAX - left) throw std::invalid_argument(message);
  return left + right;
}
}  // namespace

class ThresholdProtocolClient::Impl {
 public:
  Impl(std::string enclave_path, std::string key_directory,
       std::string csp_host, int csp_port, ThresholdMode selected_mode)
      : mode(selected_mode), enclave(createEnclave(enclave_path)),
        modulus(loadModulus(key_directory + "/public.bin")),
        modulus_squared(modulus * modulus) {
    try {
      initializeEnclave(enclave, 1, mode);
      loadShare(enclave, key_directory + "/cp.sealed");
      socket = wire::connectTcp(csp_host, csp_port);
      RSA* rsa=RSA_new();BIGNUM* exponent=BN_new();
      if(!rsa||!exponent||!BN_set_word(exponent,RSA_F4)||
         RSA_generate_key_ex(rsa,3072,exponent,nullptr)!=1){
        RSA_free(rsa);BN_free(exponent);throw std::runtime_error("predicate OT keygen failed");
      }
      const BIGNUM *n,*e,*d;RSA_get0_key(rsa,&n,&e,&d);
      ot_modulus=bnToMpz(n);ot_public=bnToMpz(e);ot_private=bnToMpz(d);
      RSA_free(rsa);BN_free(exponent);
    } catch (...) {
      if (socket >= 0) close(socket);
      sgx_destroy_enclave(enclave);
      throw;
    }
  }

  ~Impl() {
    if (socket >= 0) close(socket);
    if (enclave != 0) sgx_destroy_enclave(enclave);
  }

  mpz_class randomMask() {
    // Protocol operands must obey NumericDomain; the mask and packing base
    // match the reviewed SOCI-plus implementation used by the SGX benchmark.
    return (mpz_class(1) << 127) + randomBits(127);
  }

  mpz_class encrypt(const mpz_class& plaintext) {
    const auto start=Clock::now();
    auto ciphertext=paillierEncrypt(plaintext,modulus,modulus_squared);
    metrics.host_encrypt_microseconds+=
        std::chrono::duration<double,std::micro>(Clock::now()-start).count();
    ++metrics.host_encrypt_calls;
    return ciphertext;
  }

  std::vector<mpz_class> encryptBatch(
      const std::vector<mpz_class>& plaintexts) {
    const auto start=Clock::now();
    auto ciphertexts=paillierEncryptBatch(
        plaintexts,modulus,modulus_squared,encryption_threads);
    metrics.host_encrypt_microseconds+=
        std::chrono::duration<double,std::micro>(Clock::now()-start).count();
    metrics.host_encrypt_calls+=plaintexts.size();
    return ciphertexts;
  }

  ThresholdMode mode;
  sgx_enclave_id_t enclave{};
  mpz_class modulus;
  mpz_class modulus_squared;
  mpz_class ot_modulus,ot_public,ot_private;
  const std::size_t encryption_threads{encryptionThreadCount()};
  int socket{-1};
  ProtocolMetrics metrics;
};

ThresholdProtocolClient::ThresholdProtocolClient(
    std::string enclave_path, std::string key_directory, std::string csp_host,
    int csp_port, ThresholdMode mode)
    : impl_(std::make_unique<Impl>(std::move(enclave_path),
                                  std::move(key_directory), std::move(csp_host),
                                  csp_port, mode)) {}

ThresholdProtocolClient::~ThresholdProtocolClient() = default;

mpz_class ThresholdProtocolClient::encrypt(const mpz_class& plaintext) {
  return impl_->encrypt(plaintext);
}

mpz_class ThresholdProtocolClient::add(const mpz_class& a,
                                       const mpz_class& b) const {
  return a * b % impl_->modulus_squared;
}

mpz_class ThresholdProtocolClient::scalarMultiply(
    const mpz_class& value, const mpz_class& scalar) const {
  const auto start=Clock::now();
  auto output=ciphertextPower(value,scalar,impl_->modulus_squared);
  impl_->metrics.host_scalar_powm_microseconds+=
      std::chrono::duration<double,std::micro>(Clock::now()-start).count();
  ++impl_->metrics.host_scalar_powm_calls;
  return output;
}

mpz_class ThresholdProtocolClient::secureMultiply(const mpz_class& a,
                                                  const mpz_class& b,
                                                  ProtocolMetrics* metrics) {
  const auto r1 = impl_->randomMask();
  const auto r2 = impl_->randomMask();
  const auto masked_a = add(a, encrypt(r1));
  const auto masked_b = add(b, encrypt(r2));
  const mpz_class packing_base = mpz_class(1) << 130;
  const auto packed = add(scalarMultiply(masked_a, packing_base), masked_b);
  auto* measured = metrics ? metrics : &impl_->metrics;
  double* cp = &measured->cp_enclave_microseconds;
  double* net = &measured->network_microseconds;
  auto reply = wire::request(
      impl_->socket, 'M',
      {packed, partialDecrypt(impl_->enclave, packed, impl_->mode, cp),
       packing_base},
      net);
  ++measured->logical_items; ++measured->smul_logical_items;
  ++measured->smul_dispatches; ++measured->cp_ecalls;
  measured->csp_ecalls+=2; ++measured->csp_requests;
  std::size_t offset = 0;
  auto product = wire::takeInteger(reply, offset);
  product = add(product, scalarMultiply(a, -r2));
  product = add(product, scalarMultiply(b, -r1));
  return add(product, encrypt(-r1 * r2));
}

std::vector<mpz_class> ThresholdProtocolClient::secureMultiplyBatch(
    const std::vector<std::pair<mpz_class, mpz_class>>& items,
    ProtocolMetrics* metrics) {
  if (items.empty() || items.size() > SOCI_THRESHOLD_MAX_BATCH_SIZE)
    throw std::invalid_argument("invalid SMUL batch size");
  const mpz_class packing_base = mpz_class(1) << 130;
  std::vector<mpz_class> r1, r2, packed;
  r1.reserve(items.size()); r2.reserve(items.size()); packed.reserve(items.size());
  std::vector<mpz_class> mask_plaintexts;mask_plaintexts.reserve(items.size()*2);
  for (const auto& item : items) {
    (void)item;
    r1.push_back(impl_->randomMask()); r2.push_back(impl_->randomMask());
    mask_plaintexts.push_back(r1.back());mask_plaintexts.push_back(r2.back());
  }
  const auto encrypted_masks=impl_->encryptBatch(mask_plaintexts);
  for(std::size_t i=0;i<items.size();++i) {
    const auto ma=add(items[i].first,encrypted_masks[2*i]);
    const auto mb=add(items[i].second,encrypted_masks[2*i+1]);
    packed.push_back(add(scalarMultiply(ma,packing_base),mb));
  }
  auto* measured=metrics?metrics:&impl_->metrics;
  double* cp=&measured->cp_enclave_microseconds;
  double* net=&measured->network_microseconds;
  const auto shares=partialDecryptBatch(impl_->enclave,packed,impl_->mode,cp);
  Bytes request{'B','M',1,0,0,0,0,0};
  wire::writeU32(request.data()+4,static_cast<std::uint32_t>(items.size()));
  for(std::size_t i=0;i<items.size();++i){wire::appendInteger(request,packed[i]);wire::appendInteger(request,shares[i]);wire::appendInteger(request,packing_base);}
  auto reply=wire::requestPayload(impl_->socket,std::move(request),net);
  if(reply.size()<8||reply[0]!=1||reply[1]!=0||reply[2]!=0||reply[3]!=0||wire::readU32(reply.data()+4)!=items.size()) throw std::runtime_error("bad SMUL batch response");
  std::size_t offset=8;std::vector<mpz_class> products;products.reserve(items.size());
  std::vector<mpz_class> correction_plaintexts;correction_plaintexts.reserve(items.size());
  for(std::size_t i=0;i<items.size();++i){products.push_back(wire::takeInteger(reply,offset));correction_plaintexts.push_back(-r1[i]*r2[i]);}
  if(reply.size()-offset!=8) throw std::runtime_error("bad SMUL batch timing data");
  const auto encrypted_corrections=impl_->encryptBatch(correction_plaintexts);
  std::vector<mpz_class> output;output.reserve(items.size());
  for(std::size_t i=0;i<items.size();++i){auto product=add(products[i],scalarMultiply(items[i].first,-r2[i]));product=add(product,scalarMultiply(items[i].second,-r1[i]));output.push_back(add(product,encrypted_corrections[i]));}
  measured->csp_enclave_microseconds+=wire::readU64(reply.data()+offset)/1000.0;
  measured->logical_items+=items.size();measured->smul_logical_items+=items.size();
  ++measured->smul_dispatches;++measured->cp_ecalls;++measured->csp_ecalls;
  ++measured->csp_requests;
  return output;
}

mpz_class ThresholdProtocolClient::greaterThan(const mpz_class& a,
                                               const mpz_class& b,
                                               ProtocolMetrics* metrics) {
  // SOCI-plus primitive below produces Enc(left < right), so swap public
  // arguments to implement the stable SecureOps contract Enc(a > b).
  const auto& left = b;
  const auto& right = a;
  const auto r3 = impl_->randomMask();
  mpz_class r;
  do r = impl_->randomMask();
  while (r >= r3);
  const mpz_class r4 = impl_->modulus / 2 - r;
  const bool orientation = randomBits(1) != 0;
  mpz_class difference;
  if (!orientation) {
    difference = add(left, scalarMultiply(right, impl_->modulus - 1));
    difference = add(scalarMultiply(difference, r3), encrypt(r3 + r4));
  } else {
    difference = add(right, scalarMultiply(left, -1));
    difference = add(scalarMultiply(difference, r3), encrypt(r4));
  }
  if (difference <= 0 || difference >= impl_->modulus_squared ||
      gcd(difference, impl_->modulus) != 1)
    throw std::runtime_error("SCMP produced invalid ciphertext");
  auto* measured = metrics ? metrics : &impl_->metrics;
  double* cp = &measured->cp_enclave_microseconds;
  double* net = &measured->network_microseconds;
  auto reply = wire::request(
      impl_->socket, 'C',
      {difference,
       partialDecrypt(impl_->enclave, difference, impl_->mode, cp)},
      net);
  ++measured->logical_items; ++measured->scmp_logical_items;
  ++measured->scmp_dispatches; ++measured->cp_ecalls;
  measured->csp_ecalls+=2; ++measured->csp_requests;
  std::size_t offset = 0;
  const auto bit = wire::takeInteger(reply, offset);
  return orientation ? add(encrypt(1), scalarMultiply(bit, -1)) : bit;
}

std::vector<mpz_class> ThresholdProtocolClient::greaterThanBatch(
    const std::vector<std::pair<mpz_class, mpz_class>>& items,
    ProtocolMetrics* metrics) {
  if(items.empty()||items.size()>SOCI_THRESHOLD_MAX_BATCH_SIZE) throw std::invalid_argument("invalid SCMP batch size");
  std::vector<bool> orientations;std::vector<mpz_class> differences,r3s,r4s;
  orientations.reserve(items.size());differences.reserve(items.size());
  r3s.reserve(items.size());r4s.reserve(items.size());
  std::vector<mpz_class> mask_plaintexts;mask_plaintexts.reserve(items.size());
  for(const auto& item:items){(void)item;const auto r3=impl_->randomMask();mpz_class r;do r=impl_->randomMask();while(r>=r3);const mpz_class r4=impl_->modulus/2-r;const bool orientation=randomBits(1)!=0;orientations.push_back(orientation);r3s.push_back(r3);r4s.push_back(r4);mask_plaintexts.push_back(orientation?r4:r3+r4);}
  const auto encrypted_masks=impl_->encryptBatch(mask_plaintexts);
  for(std::size_t i=0;i<items.size();++i){const auto& left=items[i].second;const auto& right=items[i].first;mpz_class difference;
    if(!orientations[i]){difference=add(left,scalarMultiply(right,impl_->modulus-1));difference=add(scalarMultiply(difference,r3s[i]),encrypted_masks[i]);}
    else{difference=add(right,scalarMultiply(left,-1));difference=add(scalarMultiply(difference,r3s[i]),encrypted_masks[i]);}
    if(difference<=0||difference>=impl_->modulus_squared||gcd(difference,impl_->modulus)!=1)throw std::runtime_error("SCMP produced invalid ciphertext");differences.push_back(std::move(difference));}
  auto* measured=metrics?metrics:&impl_->metrics;double* cp=&measured->cp_enclave_microseconds;double* net=&measured->network_microseconds;
  const auto shares=partialDecryptBatch(impl_->enclave,differences,impl_->mode,cp);
  Bytes request{'B','C',1,0,0,0,0,0};wire::writeU32(request.data()+4,static_cast<std::uint32_t>(items.size()));
  for(std::size_t i=0;i<items.size();++i){wire::appendInteger(request,differences[i]);wire::appendInteger(request,shares[i]);}
  auto reply=wire::requestPayload(impl_->socket,std::move(request),net);
  if(reply.size()<8||reply[0]!=1||reply[1]!=0||reply[2]!=0||reply[3]!=0||wire::readU32(reply.data()+4)!=items.size())throw std::runtime_error("bad SCMP batch response");
  std::size_t offset=8;std::vector<mpz_class> output;output.reserve(items.size());for(std::size_t i=0;i<items.size();++i){const auto bit=wire::takeInteger(reply,offset);output.push_back(orientations[i]?add(encrypt(1),scalarMultiply(bit,-1)):bit);}if(reply.size()-offset!=8)throw std::runtime_error("bad SCMP batch timing data");measured->csp_enclave_microseconds+=wire::readU64(reply.data()+offset)/1000.0;
  measured->logical_items+=items.size();measured->scmp_logical_items+=items.size();
  ++measured->scmp_dispatches;++measured->cp_ecalls;++measured->csp_ecalls;
  ++measured->csp_requests;return output;
}

bool ThresholdProtocolClient::fusedPredicate(
    const secure::PredicateContext& context,
    const std::vector<std::pair<mpz_class,mpz_class>>& items,
    bool has_incumbent) {
  if(items.empty()||items.size()>SOCI_THRESHOLD_MAX_BATCH_SIZE)
    throw secure::PredicateError("invalid fused predicate batch size");
  try {
    std::vector<bool> orientation;std::vector<mpz_class> differences;
    std::vector<mpz_class> masks;orientation.reserve(items.size());masks.reserve(items.size());
    std::vector<mpz_class> r3s; r3s.reserve(items.size());
    for(const auto& item:items){(void)item;auto r3=impl_->randomMask();mpz_class r;do r=impl_->randomMask();while(r>=r3);bool o=randomBits(1)!=0;orientation.push_back(o);r3s.push_back(r3);mpz_class mask=o?mpz_class(impl_->modulus/2-r):mpz_class(r3+impl_->modulus/2-r);masks.push_back(std::move(mask));}
    const auto encrypted_masks=impl_->encryptBatch(masks);
    for(std::size_t i=0;i<items.size();++i){const auto&left=items[i].second;const auto&right=items[i].first;auto d=!orientation[i]?add(left,scalarMultiply(right,impl_->modulus-1)):add(right,scalarMultiply(left,-1));d=add(scalarMultiply(d,r3s[i]),encrypted_masks[i]);if(d<=0||d>=impl_->modulus_squared||gcd(d,impl_->modulus)!=1)throw std::runtime_error("invalid fused SCMP ciphertext");differences.push_back(std::move(d));}
    auto shares=partialDecryptBatch(impl_->enclave,differences,impl_->mode,&impl_->metrics.cp_enclave_microseconds);
    const auto& n=impl_->ot_modulus;const auto& pub=impl_->ot_public;const auto& priv=impl_->ot_private;
    std::vector<mpz_class>x0,x1;x0.reserve(items.size());x1.reserve(items.size());
    Bytes request{'F',static_cast<std::uint8_t>(context.predicate_type),static_cast<std::uint8_t>(has_incumbent),0,0,0,0,0};wire::writeU32(request.data()+4,context.depth);appendContextString(request,context.session_id);appendContextString(request,context.operation_id);appendContextString(request,context.node_id);const auto co=request.size();request.resize(co+4);wire::writeU32(request.data()+co,items.size());wire::appendInteger(request,n);wire::appendInteger(request,pub);
    for(std::size_t i=0;i<items.size();++i){x0.push_back(randomBelowNonzero(n));x1.push_back(randomBelowNonzero(n));wire::appendInteger(request,differences[i]);wire::appendInteger(request,shares[i]);wire::appendInteger(request,x0[i]);wire::appendInteger(request,x1[i]);}
    const auto f_start=Clock::now();
    auto reply=wire::requestPayload(impl_->socket,std::move(request),&impl_->metrics.network_microseconds);
    impl_->metrics.fused_f_request_microseconds+=std::chrono::duration<double,std::micro>(Clock::now()-f_start).count();
    if(reply.size()<4||wire::readU32(reply.data())!=items.size())throw std::runtime_error("bad fused predicate OT response");std::size_t off=4;std::vector<mpz_class>v;for(std::size_t i=0;i<items.size();++i)v.push_back(wire::takeInteger(reply,off));if(off!=reply.size())throw std::runtime_error("trailing fused OT response");
    const auto garble_start=Clock::now();
    auto garbled=garblePredicate(context.predicate_type,items.size(),has_incumbent);
    impl_->metrics.fused_garble_microseconds+=std::chrono::duration<double,std::micro>(Clock::now()-garble_start).count();
    Bytes finish{'G',static_cast<std::uint8_t>(context.predicate_type),0,0,0,0,0,0};wire::writeU32(finish.data()+4,context.depth);appendContextString(finish,context.session_id);appendContextString(finish,context.operation_id);appendContextString(finish,context.node_id);const auto go=finish.size();finish.resize(go+8);wire::writeU32(finish.data()+go,items.size());wire::writeU32(finish.data()+go+4,garbled.tables.size());
    const auto private_powm_start=Clock::now();
    for(std::size_t i=0;i<items.size();++i){mpz_class k0,k1,b0=(v[i]-x0[i])%n,b1=(v[i]-x1[i])%n;if(b0<0)b0+=n;if(b1<0)b1+=n;mpz_powm(k0.get_mpz_t(),b0.get_mpz_t(),priv.get_mpz_t(),n.get_mpz_t());mpz_powm(k1.get_mpz_t(),b1.get_mpz_t(),priv.get_mpz_t(),n.get_mpz_t());auto l0=orientation[i]?labelXor(garbled.zero[i],garbled.delta):garbled.zero[i];auto l1=orientation[i]?garbled.zero[i]:labelXor(garbled.zero[i],garbled.delta);appendLabel(finish,labelXor(l0,otPad(k0,i)));appendLabel(finish,labelXor(l1,otPad(k1,i)));}
    impl_->metrics.fused_cp_rsa_private_powm_microseconds+=std::chrono::duration<double,std::micro>(Clock::now()-private_powm_start).count();
    for(const auto&t:garbled.tables)for(const auto&row:t)appendLabel(finish,row);appendLabel(finish,garbled.zero[garbled.circuit.output]);appendLabel(finish,labelXor(garbled.zero[garbled.circuit.output],garbled.delta));
    const auto g_start=Clock::now();
    auto decision=wire::requestPayload(impl_->socket,std::move(finish),&impl_->metrics.network_microseconds);
    impl_->metrics.fused_g_request_microseconds+=std::chrono::duration<double,std::micro>(Clock::now()-g_start).count();
    if(decision.size()!=1||decision[0]>1)throw std::runtime_error("bad fused predicate decision");auto&m=impl_->metrics;m.logical_items+=items.size();m.scmp_logical_items+=items.size();++m.scmp_dispatches;++m.cp_ecalls;m.csp_ecalls+=1;m.csp_requests+=2;++m.predicate_reveals;m.secure_bit_and_items+=garbled.tables.size();return decision[0]!=0;
  } catch(const std::exception&){throw secure::PredicateError("fused predicate protocol failed");}
}

mpz_class ThresholdProtocolClient::decryptForTesting(
    const mpz_class& ciphertext, ProtocolMetrics* metrics) {
  double* cp = metrics ? &metrics->cp_enclave_microseconds : nullptr;
  double* net = metrics ? &metrics->network_microseconds : nullptr;
  auto reply = wire::request(
      impl_->socket, 'D',
      {ciphertext,
       partialDecrypt(impl_->enclave, ciphertext, impl_->mode, cp)},
      net);
  std::size_t offset = 0;
  auto plaintext = wire::takeInteger(reply, offset);
  return plaintext > impl_->modulus / 2 ? plaintext - impl_->modulus
                                        : plaintext;
}

bool ThresholdProtocolClient::revealFinalPredicate(
    const secure::PredicateContext& context, const mpz_class& encrypted_bit,
    ProtocolMetrics* metrics) {
  auto* measured=metrics?metrics:&impl_->metrics;
  double* cp=&measured->cp_enclave_microseconds;
  double* net=&measured->network_microseconds;
  try {
    Bytes request{'P', static_cast<std::uint8_t>(context.predicate_type), 0, 0,
                  0,   0, 0, 0};
    wire::writeU32(request.data() + 4, context.depth);
    appendContextString(request, context.session_id);
    appendContextString(request, context.operation_id);
    appendContextString(request, context.node_id);
    wire::appendInteger(request, encrypted_bit);
    wire::appendInteger(
        request, partialDecrypt(impl_->enclave, encrypted_bit, impl_->mode, cp));
    auto reply = wire::requestPayload(impl_->socket, std::move(request), net);
    if (reply.size() != 1 || reply.front() > 1)
      throw secure::PredicateError("invalid threshold predicate response");
    ++measured->predicate_reveals;++measured->cp_ecalls;
    measured->csp_ecalls+=2;++measured->csp_requests;
    return reply.front() == 1;
  } catch (const secure::PredicateError&) {
    throw;
  } catch (const std::exception&) {
    throw secure::PredicateError("threshold predicate reveal failed");
  }
}

void ThresholdProtocolClient::requestServerShutdown() {
  wire::request(impl_->socket, 'Q', {});
}

const mpz_class& ThresholdProtocolClient::modulus() const noexcept {
  return impl_->modulus;
}

ThresholdMode ThresholdProtocolClient::mode() const noexcept {
  return impl_->mode;
}

const ProtocolMetrics& ThresholdProtocolClient::metrics() const noexcept {
  return impl_->metrics;
}

void ThresholdProtocolClient::refreshCspMetrics() {
  auto reply=wire::requestPayload(impl_->socket,Bytes{'T'});
  if(reply.size()!=64||std::memcmp(reply.data(),"CSTM",4)||reply[4]!=1||
     reply[5]!=0||reply[6]!=0||reply[7]!=0)
    throw std::runtime_error("bad CSP timing response");
  impl_->metrics.csp_request_microseconds=wire::readU64(reply.data()+8)/1000.0;
  impl_->metrics.csp_enclave_microseconds=wire::readU64(reply.data()+16)/1000.0;
  impl_->metrics.csp_encrypt_microseconds=wire::readU64(reply.data()+24)/1000.0;
  impl_->metrics.csp_parse_serialize_microseconds=wire::readU64(reply.data()+32)/1000.0;
  impl_->metrics.csp_socket_send_microseconds=wire::readU64(reply.data()+40)/1000.0;
  impl_->metrics.fused_csp_rsa_public_powm_microseconds=wire::readU64(reply.data()+48)/1000.0;
  impl_->metrics.fused_circuit_evaluate_microseconds=wire::readU64(reply.data()+56)/1000.0;
}

ThresholdSecureOps::ThresholdSecureOps(ThresholdProtocolClient& protocol,
                                       secure::NumericDomain domain)
    : protocol_(protocol), domain_(domain) {
  // The 128-bit mask is sampled from [2^127, 2^128).  Keeping every signed
  // plaintext that can enter SMUL at |x| < 2^127 makes both masked operands
  // positive and strictly smaller than the 2^130 packing base.
  constexpr std::uint32_t kSignedPlaintextBits = 127;
  constexpr std::uint32_t kLinearSignMargin = 1;
  if (domain_.scale <= 0 || domain_.max_rows == 0 ||
      domain_.max_cost_bits == 0 || domain_.max_total_bits == 0 ||
      domain_.max_linear_bits == 0 || domain_.compare_operand_bits == 0)
    throw std::invalid_argument(
        "ThresholdSecureOps requires a complete NumericDomain");

  const auto required_total_bits = checkedBitSum(
      domain_.max_cost_bits, ceilLog2(domain_.max_rows),
      "NumericDomain total bit calculation overflowed");
  auto required_linear_bits = checkedBitSum(
      required_total_bits,
      ceilLog2(static_cast<std::uint64_t>(domain_.scale)),
      "NumericDomain linear bit calculation overflowed");
  required_linear_bits = checkedBitSum(
      required_linear_bits, kLinearSignMargin,
      "NumericDomain linear bit calculation overflowed");
  const auto required_compare_bits =
      std::max(required_total_bits, required_linear_bits);

  if (domain_.max_total_bits < required_total_bits ||
      domain_.max_linear_bits < required_linear_bits ||
      domain_.compare_operand_bits < required_compare_bits)
    throw std::invalid_argument(
        "NumericDomain declared bounds are smaller than derived bounds");
  if (domain_.max_cost_bits > kSignedPlaintextBits ||
      domain_.max_total_bits > kSignedPlaintextBits ||
      domain_.max_linear_bits > kSignedPlaintextBits ||
      domain_.compare_operand_bits > kSignedPlaintextBits)
    throw std::invalid_argument(
        "NumericDomain violates the SMUL invariant |x| < 2^127");
}

secure::Ciphertext ThresholdSecureOps::encryptConstant(std::int64_t value) {
  return decodeCiphertext(protocol_.encrypt(value), protocol_.mode());
}

secure::Ciphertext ThresholdSecureOps::add(const secure::Ciphertext& a,
                                           const secure::Ciphertext& b) {
  return decodeCiphertext(protocol_.add(encodeCiphertext(a, protocol_.mode()),
                                        encodeCiphertext(b, protocol_.mode())),
                          protocol_.mode());
}

secure::Ciphertext ThresholdSecureOps::scalarMul(const secure::Ciphertext& a,
                                                 std::int64_t scalar) {
  return decodeCiphertext(protocol_.scalarMultiply(
                              encodeCiphertext(a, protocol_.mode()), scalar),
                          protocol_.mode());
}

secure::Ciphertext ThresholdSecureOps::secureMul(const secure::Ciphertext& a,
                                                 const secure::Ciphertext& b) {
  const auto values=protocol_.secureMultiplyBatch({{
      encodeCiphertext(a,protocol_.mode()),
      encodeCiphertext(b,protocol_.mode())}});
  return decodeCiphertext(values.front(),protocol_.mode());
}

std::vector<secure::Ciphertext> ThresholdSecureOps::secureMulBatch(const std::vector<std::pair<secure::Ciphertext,secure::Ciphertext>>& items){std::vector<std::pair<mpz_class,mpz_class>> native;native.reserve(items.size());for(const auto& item:items)native.emplace_back(encodeCiphertext(item.first,protocol_.mode()),encodeCiphertext(item.second,protocol_.mode()));auto values=protocol_.secureMultiplyBatch(native);std::vector<secure::Ciphertext> output;output.reserve(values.size());for(const auto& value:values)output.push_back(decodeCiphertext(value,protocol_.mode()));return output;}

secure::EncryptedBit ThresholdSecureOps::greaterThan(
    const secure::Ciphertext& a, const secure::Ciphertext& b) {
  const auto values=protocol_.greaterThanBatch({{
      encodeCiphertext(a,protocol_.mode()),
      encodeCiphertext(b,protocol_.mode())}});
  return encryptedBit(decodeCiphertext(values.front(),protocol_.mode()));
}

std::vector<secure::EncryptedBit> ThresholdSecureOps::greaterThanBatch(const std::vector<std::pair<secure::Ciphertext,secure::Ciphertext>>& items){std::vector<std::pair<mpz_class,mpz_class>> native;native.reserve(items.size());for(const auto& item:items)native.emplace_back(encodeCiphertext(item.first,protocol_.mode()),encodeCiphertext(item.second,protocol_.mode()));auto values=protocol_.greaterThanBatch(native);std::vector<secure::EncryptedBit> output;output.reserve(values.size());for(const auto& value:values)output.push_back(encryptedBit(decodeCiphertext(value,protocol_.mode())));return output;}

bool ThresholdSecureOps::fusedPruneNode(const secure::PredicateContext& context,
                                        const secure::PruneInputs& inputs){
  std::vector<std::pair<mpz_class,mpz_class>> comparisons;
  const auto zero=protocol_.encrypt(0);comparisons.emplace_back(zero,encodeCiphertext(inputs.linear_upper,protocol_.mode()));
  if(inputs.has_incumbent)for(const auto&lower:inputs.cost_lowers)comparisons.emplace_back(encodeCiphertext(lower,protocol_.mode()),encodeCiphertext(inputs.incumbent_cost,protocol_.mode()));
  return protocol_.fusedPredicate(context,comparisons,inputs.has_incumbent);
}

bool ThresholdSecureOps::predicateFusionEnabled() const noexcept {
  const char* value=std::getenv("SOCI_PREDICATE_FUSION");
  return !value||std::strcmp(value,"0")!=0;
}

bool ThresholdSecureOps::fusedAcceptCandidate(const secure::PredicateContext& context,
                                              const secure::AcceptInputs& inputs){
  const auto zero=protocol_.encrypt(0);std::vector<std::pair<mpz_class,mpz_class>> comparisons{{zero,encodeCiphertext(inputs.linear,protocol_.mode())},{encodeCiphertext(inputs.c3,protocol_.mode()),zero}};
  if(inputs.has_incumbent){comparisons.emplace_back(encodeCiphertext(inputs.incumbent_cost,protocol_.mode()),encodeCiphertext(inputs.cost,protocol_.mode()));comparisons.emplace_back(encodeCiphertext(inputs.cost,protocol_.mode()),encodeCiphertext(inputs.incumbent_cost,protocol_.mode()));comparisons.emplace_back(encodeCiphertext(inputs.incumbent_c12,protocol_.mode()),encodeCiphertext(inputs.c12,protocol_.mode()));}
  return protocol_.fusedPredicate(context,comparisons,inputs.has_incumbent);
}

bool ThresholdPredicateBitResolver::revealFinalBit(
    const secure::PredicateContext& context,
    const secure::EncryptedBit& bit) {
  return protocol_.revealFinalPredicate(
      context, encodeCiphertext(bit.ciphertext(), protocol_.mode()));
}

int provisionThresholdKeys(const std::string& enclave_path,
                           const std::string& directory, unsigned bits,
                           ThresholdMode mode) {
  const auto enclave = createEnclave(enclave_path);
  try {
    initializeEnclave(enclave, 0, mode);
    std::uint8_t request[12] = {'S', 'K', 'G', 'N', 1, modeByte(mode),
                                0,   0,   0,   0,   0, 0};
    wire::writeU32(request + 8, bits);
    Bytes output(3 * 1024 * 1024);
    std::size_t output_size = 0;
    std::uint32_t result = 0;
    const auto start = Clock::now();
    const auto status = ecall_threshold_keygen(
        enclave, &result, request, sizeof(request), output.data(), output.size(),
        &output_size);
    const auto milliseconds =
        std::chrono::duration<double, std::milli>(Clock::now() - start).count();
    if (status != SGX_SUCCESS || result != 0 || output_size < 24 ||
        std::memcmp(output.data(), "STKO", 4) != 0)
      throw std::runtime_error("threshold keygen failed");
    const auto public_size = wire::readU32(output.data() + 12);
    const auto cp_size = wire::readU32(output.data() + 16);
    const auto csp_size = wire::readU32(output.data() + 20);
    if (24ull + public_size + cp_size + csp_size != output_size)
      throw std::runtime_error("bad key package");
    wire::writeFile(directory + "/public.bin", output.data() + 24,
                    public_size);
    wire::writeFile(directory + "/cp.sealed",
                    output.data() + 24 + public_size, cp_size);
    wire::writeFile(directory + "/csp.sealed",
                    output.data() + 24 + public_size + cp_size, csp_size);
    std::cout << "{\"mode\":\"" << thresholdModeName(mode)
              << "\",\"role\":\"Provisioning\",\"operation\":\"KeyGen\","
                 "\"security_bits\":128,\"modulus_bits\":"
              << bits << ",\"milliseconds\":" << milliseconds << "}\n";
    sgx_destroy_enclave(enclave);
    return 0;
  } catch (...) {
    sgx_destroy_enclave(enclave);
    throw;
  }
}

int runThresholdCsp(const std::string& enclave_path,
                    const std::string& key_directory, int port,
                    ThresholdMode mode) {
  const auto enclave = createEnclave(enclave_path);
  initializeEnclave(enclave, 2, mode);
  loadShare(enclave, key_directory + "/csp.sealed");
  const auto modulus = loadModulus(key_directory + "/public.bin");
  const mpz_class modulus_squared = modulus * modulus;
  auto encrypt = [&](const mpz_class& plaintext) -> mpz_class {
    return paillierEncrypt(plaintext,modulus,modulus_squared);
  };
  const auto encryption_threads=encryptionThreadCount();

  const int listener = socket(AF_INET, SOCK_STREAM, 0);
  int enabled = 1;
  setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled));
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = INADDR_ANY;
  address.sin_port = htons(port);
  if (bind(listener, reinterpret_cast<sockaddr*>(&address), sizeof(address)) ||
      listen(listener, 8))
    throw std::runtime_error("listen failed");
  struct CspTimings {
    std::uint64_t request_ns{};
    std::uint64_t threshold_decrypt_ns{};
    std::uint64_t encrypt_ns{};
    std::uint64_t parse_serialize_ns{};
    std::uint64_t socket_send_ns{};
    std::uint64_t fused_rsa_public_powm_ns{};
    std::uint64_t fused_circuit_evaluate_ns{};
  } timings;
  struct PendingFused {std::string session,operation,node;secure::PredicateType type{};bool incumbent{};std::uint32_t depth{};std::vector<bool> choices;std::vector<mpz_class> keys;BooleanCircuit circuit;};
  std::optional<PendingFused> pending_fused;std::unordered_set<std::string> fused_replays;
  const auto elapsedNs=[](Clock::time_point start) {
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            Clock::now()-start).count());
  };
  std::cerr << "CSP ready on " << port << '\n';
  for (;;) {
    const int socket = accept(listener, nullptr, nullptr);
    if (socket < 0) continue;
    try {
      wire::setTcpNoDelay(socket);
      for (;;) {
        const auto request = wire::receiveFrame(socket);
        const auto request_start=Clock::now();
        if (request.empty()) throw std::runtime_error("empty request");
        const char operation = request.front();
        if(operation=='F'){
          if(pending_fused||request.size()<8||request[1]<1||request[1]>2||
             request[2]>1||request[3]!=0)
            throw std::runtime_error("invalid fused predicate start");
          std::size_t o=8;PendingFused p;
          p.type=static_cast<secure::PredicateType>(request[1]);
          p.incumbent=request[2]!=0;
          p.depth=wire::readU32(request.data()+4);
          p.session=takeContextString(request,o);
          p.operation=takeContextString(request,o);
          p.node=takeContextString(request,o);
          if(request.size()-o<4)throw std::runtime_error("short fused predicate start");
          const auto count=wire::readU32(request.data()+o);o+=4;
          if(!count||count>SOCI_THRESHOLD_MAX_BATCH_SIZE)
            throw std::runtime_error("bad fused comparison count");
          const auto rsa_n=wire::takeInteger(request,o);
          const auto rsa_e=wire::takeInteger(request,o);
          if(mpz_sizeinbase(rsa_n.get_mpz_t(),2)!=3072||rsa_e!=RSA_F4)
            throw std::runtime_error("bad fused OT key");
          std::vector<mpz_class>ciphertexts,cp_shares,x0,x1;
          for(std::uint32_t i=0;i<count;++i){
            ciphertexts.push_back(wire::takeInteger(request,o));
            cp_shares.push_back(wire::takeInteger(request,o));
            x0.push_back(wire::takeInteger(request,o));
            x1.push_back(wire::takeInteger(request,o));
            if(x0.back()<=0||x0.back()>=rsa_n||x1.back()<=0||x1.back()>=rsa_n)
              throw std::runtime_error("bad fused OT nonce");
          }
          if(o!=request.size())throw std::runtime_error("trailing fused start");
          const auto replay=p.session+'\0'+p.operation;
          if(!fused_replays.insert(replay).second)
            throw std::runtime_error("fused predicate replay");
          p.circuit=predicateCircuit(p.type,count,p.incumbent);
          const auto decrypt_start=Clock::now();
          const auto plain=thresholdDecryptBatch(enclave,ciphertexts,cp_shares,mode);
          timings.threshold_decrypt_ns+=elapsedNs(decrypt_start);
          Bytes response{0,0,0,0,0};wire::writeU32(response.data()+1,count);
          const auto public_powm_start=Clock::now();
          for(std::uint32_t i=0;i<count;++i){
            const bool choice=plain[i]<=modulus/2;p.choices.push_back(choice);
            auto k=randomBelowNonzero(rsa_n);p.keys.push_back(k);mpz_class ke;
            mpz_powm(ke.get_mpz_t(),k.get_mpz_t(),rsa_e.get_mpz_t(),rsa_n.get_mpz_t());
            mpz_class v=(choice?x1[i]:x0[i])+ke;v%=rsa_n;
            wire::appendInteger(response,v);
          }
          timings.fused_rsa_public_powm_ns+=elapsedNs(public_powm_start);
          pending_fused=std::move(p);wire::sendFrame(socket,response);continue;
        }
        if(operation=='G'){
          if(!pending_fused||request.size()<8||request[1]<1||request[1]>2||
             request[2]!=0||request[3]!=0)
            throw std::runtime_error("invalid fused predicate finish");
          auto p=std::move(*pending_fused);pending_fused.reset();
          const auto type=static_cast<secure::PredicateType>(request[1]);
          const auto depth=wire::readU32(request.data()+4);
          std::size_t o=8;
          const auto session=takeContextString(request,o);
          const auto op=takeContextString(request,o);
          const auto node=takeContextString(request,o);
          if(session!=p.session||op!=p.operation||type!=p.type||
             depth!=p.depth||node!=p.node||request.size()-o<8)
            throw std::runtime_error("fused context mismatch");
          const auto count=wire::readU32(request.data()+o);
          const auto gates=wire::readU32(request.data()+o+4);o+=8;
          if(count!=p.choices.size()||gates!=p.circuit.and_gates.size())
            throw std::runtime_error("fused circuit shape mismatch");
          const auto evaluate_start=Clock::now();
          std::vector<Label>labels(p.circuit.wires.size());
          for(std::uint32_t i=0;i<count;++i){
            auto m0=takeLabel(request,o),m1=takeLabel(request,o);
            labels[i]=labelXor(p.choices[i]?m1:m0,otPad(p.keys[i],i));
          }
          std::vector<std::array<Label,4>>tables(gates);
          for(auto&t:tables)for(auto&row:t)row=takeLabel(request,o);
          const auto out0=takeLabel(request,o),out1=takeLabel(request,o);
          if(o!=request.size())throw std::runtime_error("trailing fused finish");
          std::size_t gi=0;
          for(std::uint32_t w=count;w<labels.size();++w){
            const auto&lin=p.circuit.wires[w];
            if(!lin.terms.empty()){
              Label z{};for(auto t:lin.terms)z=labelXor(z,labels.at(t));labels[w]=z;
            }else{
              const auto&gate=p.circuit.and_gates.at(gi);
              auto pad=gatePad(labels.at(gate.left),labels.at(gate.right),gi);
              const auto row=((labels[gate.left].back()&1)<<1)|
                             (labels[gate.right].back()&1);
              labels[w]=labelXor(pad,tables[gi][row]);++gi;
            }
          }
          Bytes response{0};
          if(labels[p.circuit.output]==out0)response.push_back(0);
          else if(labels[p.circuit.output]==out1)response.push_back(1);
          else throw std::runtime_error("invalid fused output label");
          timings.fused_circuit_evaluate_ns+=elapsedNs(evaluate_start);
          wire::sendFrame(socket,response);continue;
        }
        if(operation=='T') {
          if(request.size()!=1) throw std::runtime_error("invalid timing request");
          Bytes reply{0,'C','S','T','M',1,0,0,0};
          wire::appendU64(reply,timings.request_ns);
          wire::appendU64(reply,timings.threshold_decrypt_ns);
          wire::appendU64(reply,timings.encrypt_ns);
          wire::appendU64(reply,timings.parse_serialize_ns);
          wire::appendU64(reply,timings.socket_send_ns);
          wire::appendU64(reply,timings.fused_rsa_public_powm_ns);
          wire::appendU64(reply,timings.fused_circuit_evaluate_ns);
          wire::sendFrame(socket,reply);
          continue;
        }
        if (operation == 'B') {
          if (request.size() < 8 || (request[1] != 'C' && request[1] != 'M') ||
              request[2] != 1 || request[3] != 0)
            throw std::runtime_error("invalid batch header");
          const auto count = wire::readU32(request.data() + 4);
          if (count == 0 || count > SOCI_THRESHOLD_MAX_BATCH_SIZE)
            throw std::runtime_error("invalid batch count");
          std::size_t batch_offset = 8;
          struct BatchItem { mpz_class ciphertext, cp_share, base; };
          std::vector<BatchItem> batch; batch.reserve(count);
          for (std::uint32_t i=0;i<count;++i) {
            BatchItem item;
            item.ciphertext=wire::takeInteger(request,batch_offset);
            item.cp_share=wire::takeInteger(request,batch_offset);
            if(request[1]=='M') item.base=wire::takeInteger(request,batch_offset);
            batch.push_back(std::move(item));
          }
          if(batch_offset!=request.size()) throw std::runtime_error("trailing batch request data");
          // Validate every item before executing any protocol instance.
          for(const auto& item:batch) if(item.ciphertext<=0||item.ciphertext>=modulus_squared||(request[1]=='M'&&item.base<=1)) throw std::runtime_error("invalid batch item");
          timings.parse_serialize_ns+=elapsedNs(request_start);
          // Leading status byte is consumed by requestPayload; the remaining
          // response is version/reserved/count.
          Bytes reply{0,1,0,0,0,0,0,0,0}; wire::writeU32(reply.data()+5,count);
          std::vector<mpz_class> ciphertexts,cp_shares;
          ciphertexts.reserve(count);cp_shares.reserve(count);
          for(const auto& item:batch){ciphertexts.push_back(item.ciphertext);cp_shares.push_back(item.cp_share);}
          const auto csp_ecall_start=Clock::now();
          const auto plaintexts=thresholdDecryptBatch(enclave,ciphertexts,cp_shares,mode);
          const auto csp_ecall_ns=elapsedNs(csp_ecall_start);
          timings.threshold_decrypt_ns+=csp_ecall_ns;
          std::vector<mpz_class> result_plaintexts;result_plaintexts.reserve(count);
          for(std::size_t i=0;i<batch.size();++i){const auto& item=batch[i];const auto& plaintext=plaintexts[i];if(request[1]=='M'){const auto masked_a=plaintext/item.base;const auto masked_b=plaintext%item.base;result_plaintexts.push_back(masked_a*masked_b);}else result_plaintexts.push_back(plaintext>modulus/2?0:1);}
          const auto encrypt_start=Clock::now();
          const auto results=paillierEncryptBatch(
              result_plaintexts,modulus,modulus_squared,encryption_threads);
          timings.encrypt_ns+=elapsedNs(encrypt_start);
          const auto serialize_start=Clock::now();
          for(const auto& result:results) wire::appendInteger(reply,result);
          wire::appendU64(reply,csp_ecall_ns);
          timings.parse_serialize_ns+=elapsedNs(serialize_start);
          const auto send_start=Clock::now();
          wire::sendFrame(socket,reply);
          timings.socket_send_ns+=elapsedNs(send_start);
          timings.request_ns+=elapsedNs(request_start);
          continue;
        }
        if (operation == 'P') {
          if (request.size() < 8 || request[1] < 1 || request[1] > 2 ||
              request[2] != 0 || request[3] != 0)
            throw std::runtime_error("invalid predicate request header");
          std::size_t predicate_offset = 8;
          const auto session_id =
              takeContextString(request, predicate_offset);
          const auto operation_id =
              takeContextString(request, predicate_offset);
          const auto node_id = takeContextString(request, predicate_offset);
          const auto ciphertext =
              wire::takeInteger(request, predicate_offset);
          const auto cp_share = wire::takeInteger(request, predicate_offset);
          if (predicate_offset != request.size())
            throw std::runtime_error("trailing predicate request data");
          (void)session_id;
          (void)operation_id;
          (void)node_id;
          timings.parse_serialize_ns+=elapsedNs(request_start);
          Bytes reply{0};
          const auto decrypt_start=Clock::now();
          const auto predicate =
              combineDecrypt(enclave, cp_share,
                             partialDecrypt(enclave, ciphertext, mode), mode);
          timings.threshold_decrypt_ns+=elapsedNs(decrypt_start);
          const auto serialize_start=Clock::now();
          if (predicate != 0 && predicate != 1)
            reply.front() = 1;
          else
            reply.push_back(predicate == 1 ? 1 : 0);
          timings.parse_serialize_ns+=elapsedNs(serialize_start);
          const auto send_start=Clock::now();
          wire::sendFrame(socket, reply);
          timings.socket_send_ns+=elapsedNs(send_start);
          timings.request_ns+=elapsedNs(request_start);
          continue;
        }
        std::size_t offset = 1;
        std::vector<mpz_class> values;
        while (offset < request.size())
          values.push_back(wire::takeInteger(request, offset));
        Bytes reply{0};
        if (operation == 'Q') {
          wire::sendFrame(socket, reply);
          close(socket);
          close(listener);
          sgx_destroy_enclave(enclave);
          std::cerr << "CSP stopped after CP completion\n";
          return 0;
        }
        if (operation == 'D' && values.size() == 2) {
          wire::appendInteger(
              reply, combineDecrypt(enclave, values[1],
                                    partialDecrypt(enclave, values[0], mode),
                                    mode));
        } else if (operation == 'M' && values.size() == 3) {
          if (values[2] <= 1)
            throw std::runtime_error("invalid SMUL packing base");
          const auto plaintext =
              combineDecrypt(enclave, values[1],
                             partialDecrypt(enclave, values[0], mode), mode);
          const auto masked_a = plaintext / values[2];
          const auto masked_b = plaintext % values[2];
          wire::appendInteger(reply, encrypt(masked_a * masked_b));
        } else if (operation == 'C' && values.size() == 2) {
          const auto difference =
              combineDecrypt(enclave, values[1],
                             partialDecrypt(enclave, values[0], mode), mode);
          wire::appendInteger(reply,
                              encrypt(difference > modulus / 2 ? 0 : 1));
        } else {
          reply.front() = 1;
        }
        wire::sendFrame(socket, reply);
      }
    } catch (const std::exception& error) {
      // A broken/ambiguous transcript is never resumable.  The replay entry
      // inserted at F-start remains consumed, while all secret transient state
      // is discarded before accepting another connection.
      pending_fused.reset();
      std::cerr << "CSP request rejected: " << error.what() << '\n';
      close(socket);
    }
  }
}

const char* thresholdModeName(ThresholdMode mode) noexcept {
  return mode == ThresholdMode::sim ? "SIM" : "HW";
}

}  // namespace soci::protocol
