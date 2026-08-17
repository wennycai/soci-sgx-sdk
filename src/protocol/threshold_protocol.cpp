#include "protocol/threshold_protocol.hpp"

#include "ciphertext_codec.hpp"
#include "protocol/threshold_wire.hpp"
#include "soci_u.h"

#include <arpa/inet.h>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <sgx_urts.h>
#include <stdexcept>
#include <sys/socket.h>
#include <sys/random.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace soci::protocol {
namespace {
using Clock = std::chrono::steady_clock;
using wire::Bytes;

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
    mpz_class nonce, nonce_n;
    do nonce = randomBelow(modulus);
    while (nonce == 0 || gcd(nonce, modulus) != 1);
    mpz_powm(nonce_n.get_mpz_t(), nonce.get_mpz_t(), modulus.get_mpz_t(),
             modulus_squared.get_mpz_t());
    mpz_class normalized = plaintext % modulus;
    if (normalized < 0) normalized += modulus;
    mpz_class message_factor = normalized * modulus;
    message_factor += 1;
    mpz_class ciphertext = message_factor * nonce_n;
    ciphertext %= modulus_squared;
    return ciphertext;
  }

  ThresholdMode mode;
  sgx_enclave_id_t enclave{};
  mpz_class modulus;
  mpz_class modulus_squared;
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
  return ciphertextPower(value, scalar, impl_->modulus_squared);
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
  for (const auto& item : items) {
    r1.push_back(impl_->randomMask()); r2.push_back(impl_->randomMask());
    const auto ma=add(item.first,encrypt(r1.back()));
    const auto mb=add(item.second,encrypt(r2.back()));
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
  std::size_t offset=8;std::vector<mpz_class> output;output.reserve(items.size());
  for(std::size_t i=0;i<items.size();++i){auto product=wire::takeInteger(reply,offset);product=add(product,scalarMultiply(items[i].first,-r2[i]));product=add(product,scalarMultiply(items[i].second,-r1[i]));output.push_back(add(product,encrypt(-r1[i]*r2[i])));}
  if(offset!=reply.size()) throw std::runtime_error("trailing SMUL batch response");
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
  std::vector<bool> orientations;std::vector<mpz_class> differences;
  orientations.reserve(items.size());differences.reserve(items.size());
  for(const auto& item:items){const auto& left=item.second;const auto& right=item.first;const auto r3=impl_->randomMask();mpz_class r;do r=impl_->randomMask();while(r>=r3);const mpz_class r4=impl_->modulus/2-r;const bool orientation=randomBits(1)!=0;mpz_class difference;
    if(!orientation){difference=add(left,scalarMultiply(right,impl_->modulus-1));difference=add(scalarMultiply(difference,r3),encrypt(r3+r4));}
    else{difference=add(right,scalarMultiply(left,-1));difference=add(scalarMultiply(difference,r3),encrypt(r4));}
    if(difference<=0||difference>=impl_->modulus_squared||gcd(difference,impl_->modulus)!=1)throw std::runtime_error("SCMP produced invalid ciphertext");orientations.push_back(orientation);differences.push_back(std::move(difference));}
  auto* measured=metrics?metrics:&impl_->metrics;double* cp=&measured->cp_enclave_microseconds;double* net=&measured->network_microseconds;
  const auto shares=partialDecryptBatch(impl_->enclave,differences,impl_->mode,cp);
  Bytes request{'B','C',1,0,0,0,0,0};wire::writeU32(request.data()+4,static_cast<std::uint32_t>(items.size()));
  for(std::size_t i=0;i<items.size();++i){wire::appendInteger(request,differences[i]);wire::appendInteger(request,shares[i]);}
  auto reply=wire::requestPayload(impl_->socket,std::move(request),net);
  if(reply.size()<8||reply[0]!=1||reply[1]!=0||reply[2]!=0||reply[3]!=0||wire::readU32(reply.data()+4)!=items.size())throw std::runtime_error("bad SCMP batch response");
  std::size_t offset=8;std::vector<mpz_class> output;output.reserve(items.size());for(std::size_t i=0;i<items.size();++i){const auto bit=wire::takeInteger(reply,offset);output.push_back(orientations[i]?add(encrypt(1),scalarMultiply(bit,-1)):bit);}if(offset!=reply.size())throw std::runtime_error("trailing SCMP batch response");
  measured->logical_items+=items.size();measured->scmp_logical_items+=items.size();
  ++measured->scmp_dispatches;++measured->cp_ecalls;++measured->csp_ecalls;
  ++measured->csp_requests;return output;
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
    mpz_class nonce, nonce_n;
    do nonce = randomBelow(modulus);
    while (nonce == 0 || gcd(nonce, modulus) != 1);
    mpz_powm(nonce_n.get_mpz_t(), nonce.get_mpz_t(), modulus.get_mpz_t(),
             modulus_squared.get_mpz_t());
    mpz_class normalized = plaintext % modulus;
    if (normalized < 0) normalized += modulus;
    mpz_class message_factor = normalized * modulus;
    message_factor += 1;
    mpz_class ciphertext = message_factor * nonce_n;
    ciphertext %= modulus_squared;
    return ciphertext;
  };

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
  std::cerr << "CSP ready on " << port << '\n';
  for (;;) {
    const int socket = accept(listener, nullptr, nullptr);
    if (socket < 0) continue;
    try {
      for (;;) {
        const auto request = wire::receiveFrame(socket);
        if (request.empty()) throw std::runtime_error("empty request");
        const char operation = request.front();
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
          // Leading status byte is consumed by requestPayload; the remaining
          // response is version/reserved/count.
          Bytes reply{0,1,0,0,0,0,0,0,0}; wire::writeU32(reply.data()+5,count);
          std::vector<mpz_class> ciphertexts,cp_shares;
          ciphertexts.reserve(count);cp_shares.reserve(count);
          for(const auto& item:batch){ciphertexts.push_back(item.ciphertext);cp_shares.push_back(item.cp_share);}
          const auto plaintexts=thresholdDecryptBatch(enclave,ciphertexts,cp_shares,mode);
          std::vector<mpz_class> results;results.reserve(count);
          for(std::size_t i=0;i<batch.size();++i){const auto& item=batch[i];const auto& plaintext=plaintexts[i];if(request[1]=='M'){const auto masked_a=plaintext/item.base;const auto masked_b=plaintext%item.base;results.push_back(encrypt(masked_a*masked_b));}else results.push_back(encrypt(plaintext>modulus/2?0:1));}
          for(const auto& result:results) wire::appendInteger(reply,result);
          wire::sendFrame(socket,reply);continue;
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
          Bytes reply{0};
          const auto predicate =
              combineDecrypt(enclave, cp_share,
                             partialDecrypt(enclave, ciphertext, mode), mode);
          if (predicate != 0 && predicate != 1)
            reply.front() = 1;
          else
            reply.push_back(predicate == 1 ? 1 : 0);
          wire::sendFrame(socket, reply);
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
      std::cerr << "CSP request rejected: " << error.what() << '\n';
      close(socket);
    }
  }
}

const char* thresholdModeName(ThresholdMode mode) noexcept {
  return mode == ThresholdMode::sim ? "SIM" : "HW";
}

}  // namespace soci::protocol
