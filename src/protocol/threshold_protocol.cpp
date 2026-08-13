#include "protocol/threshold_protocol.hpp"

#include "ciphertext_codec.hpp"
#include "protocol/threshold_wire.hpp"
#include "soci_u.h"

#include <arpa/inet.h>
#include <chrono>
#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <openssl/rand.h>
#include <stdexcept>
#include <sys/socket.h>
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

mpz_class combineDecrypt(sgx_enclave_id_t enclave, const mpz_class& cp_share,
                         const mpz_class& csp_share, ThresholdMode mode) {
  Bytes request{'S', 'C', 'M', 'B', 1, modeByte(mode), 0, 0};
  wire::appendInteger(request, cp_share);
  wire::appendInteger(request, csp_share);
  Bytes response(8192);
  std::size_t response_size = 0;
  std::uint32_t result = 0;
  if (ecall_combine_decrypt(enclave, &result, request.data(), request.size(),
                            response.data(), response.size(), &response_size) !=
          SGX_SUCCESS ||
      result != 0)
    throw std::runtime_error("combine failed");
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
  const auto bytes = wire::readFile(path);
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
  if (RAND_bytes(bytes.data(), static_cast<int>(bytes.size())) != 1)
    throw std::runtime_error("OpenSSL CSPRNG failure");
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
    return ((1 + (plaintext % modulus + modulus) % modulus * modulus) *
            nonce_n) %
           modulus_squared;
  }

  ThresholdMode mode;
  sgx_enclave_id_t enclave{};
  mpz_class modulus;
  mpz_class modulus_squared;
  int socket{-1};
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
  double* cp = metrics ? &metrics->cp_enclave_microseconds : nullptr;
  double* net = metrics ? &metrics->network_microseconds : nullptr;
  auto reply = wire::request(
      impl_->socket, 'M',
      {packed, partialDecrypt(impl_->enclave, packed, impl_->mode, cp),
       packing_base},
      net);
  std::size_t offset = 0;
  auto product = wire::takeInteger(reply, offset);
  product = add(product, scalarMultiply(a, -r2));
  product = add(product, scalarMultiply(b, -r1));
  return add(product, encrypt(-r1 * r2));
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
  double* cp = metrics ? &metrics->cp_enclave_microseconds : nullptr;
  double* net = metrics ? &metrics->network_microseconds : nullptr;
  auto reply = wire::request(
      impl_->socket, 'C',
      {difference,
       partialDecrypt(impl_->enclave, difference, impl_->mode, cp)},
      net);
  std::size_t offset = 0;
  const auto bit = wire::takeInteger(reply, offset);
  return orientation ? add(encrypt(1), scalarMultiply(bit, -1)) : bit;
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

void ThresholdProtocolClient::requestServerShutdown() {
  wire::request(impl_->socket, 'Q', {});
}

const mpz_class& ThresholdProtocolClient::modulus() const noexcept {
  return impl_->modulus;
}

ThresholdMode ThresholdProtocolClient::mode() const noexcept {
  return impl_->mode;
}

ThresholdSecureOps::ThresholdSecureOps(ThresholdProtocolClient& protocol,
                                       secure::NumericDomain domain)
    : protocol_(protocol), domain_(domain) {
  constexpr std::uint32_t kProtocolOperandBits = 128;
  if (domain_.scale <= 0 || domain_.max_rows == 0 ||
      domain_.max_cost_bits == 0 || domain_.max_total_bits == 0 ||
      domain_.max_linear_bits == 0 || domain_.compare_operand_bits == 0)
    throw std::invalid_argument(
        "ThresholdSecureOps requires a complete NumericDomain");
  if (domain_.max_cost_bits > kProtocolOperandBits ||
      domain_.max_total_bits > kProtocolOperandBits ||
      domain_.max_linear_bits > kProtocolOperandBits ||
      domain_.compare_operand_bits > kProtocolOperandBits)
    throw std::invalid_argument(
        "NumericDomain exceeds the 128-bit protocol bound");
  if (domain_.max_total_bits < domain_.max_cost_bits ||
      domain_.max_linear_bits < domain_.max_cost_bits)
    throw std::invalid_argument("NumericDomain derived bounds are inconsistent");
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
  return decodeCiphertext(protocol_.secureMultiply(
                              encodeCiphertext(a, protocol_.mode()),
                              encodeCiphertext(b, protocol_.mode())),
                          protocol_.mode());
}

secure::EncryptedBit ThresholdSecureOps::greaterThan(
    const secure::Ciphertext& a, const secure::Ciphertext& b) {
  return encryptedBit(decodeCiphertext(
      protocol_.greaterThan(encodeCiphertext(a, protocol_.mode()),
                            encodeCiphertext(b, protocol_.mode())),
      protocol_.mode()));
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
  auto encrypt = [&](const mpz_class& plaintext) {
    mpz_class nonce, nonce_n;
    do nonce = randomBelow(modulus);
    while (nonce == 0 || gcd(nonce, modulus) != 1);
    mpz_powm(nonce_n.get_mpz_t(), nonce.get_mpz_t(), modulus.get_mpz_t(),
             modulus_squared.get_mpz_t());
    return ((1 + (plaintext % modulus + modulus) % modulus * modulus) *
            nonce_n) %
           modulus_squared;
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
