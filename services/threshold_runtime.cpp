#include "protocol/threshold_protocol.hpp"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace {
using Clock = std::chrono::steady_clock;
using soci::protocol::ProtocolMetrics;
using soci::protocol::ThresholdMode;
using soci::protocol::ThresholdProtocolClient;

ThresholdMode configuredMode() {
  const char* value = std::getenv("SOCI_SGX_MODE");
  return value && std::string(value) == "SIM" ? ThresholdMode::sim
                                               : ThresholdMode::hw;
}

struct Samples {
  std::string name;
  std::string security;
  std::vector<double> total;
  std::vector<double> cp;
  std::vector<double> network;
  bool correct{true};
};

double percentile(std::vector<double> values, double p) {
  std::sort(values.begin(), values.end());
  return values[std::min(values.size() - 1,
                         static_cast<std::size_t>(std::ceil(p * values.size()) -
                                                  1))];
}

void printSamples(const Samples& samples) {
  double sum = 0;
  for (double value : samples.total) sum += value;
  std::cout << "    {\"operation\":\"" << samples.name
            << "\",\"security\":\"" << samples.security
            << "\",\"samples\":" << samples.total.size()
            << ",\"mean_us\":" << sum / samples.total.size()
            << ",\"p50_us\":" << percentile(samples.total, .5)
            << ",\"p95_us\":" << percentile(samples.total, .95)
            << ",\"cp_enclave_mean_us\":";
  sum = 0;
  for (double value : samples.cp) sum += value;
  std::cout << (samples.cp.empty() ? 0 : sum / samples.cp.size())
            << ",\"csp_roundtrip_mean_us\":";
  sum = 0;
  for (double value : samples.network) sum += value;
  std::cout << (samples.network.empty() ? 0 : sum / samples.network.size())
            << ",\"correct\":" << (samples.correct ? "true" : "false")
            << '}';
}

int benchmark(const std::string& enclave_path, const std::string& directory,
              const std::string& host, int port, int warmup, int count,
              ThresholdMode mode) {
  ThresholdProtocolClient protocol(enclave_path, directory, host, port, mode);
  std::vector<Samples> all;
  auto run = [&](std::string name, std::string security, auto operation) {
    std::cerr << "CP benchmark " << name << " (warmup=" << warmup
              << ", samples=" << count << ")\n";
    Samples samples{std::move(name), std::move(security)};
    for (int sample = -warmup; sample < count; ++sample) {
      ProtocolMetrics metrics;
      const auto start = Clock::now();
      const bool correct = operation(metrics);
      const auto microseconds =
          std::chrono::duration<double, std::micro>(Clock::now() - start)
              .count();
      if (sample >= 0) {
        samples.total.push_back(microseconds);
        samples.cp.push_back(metrics.cp_enclave_microseconds);
        samples.network.push_back(metrics.network_microseconds);
        samples.correct &= correct;
      }
    }
    std::cerr << "CP benchmark " << samples.name << " complete\n";
    all.push_back(std::move(samples));
  };

  const mpz_class x = 12345;
  const mpz_class y = 67;
  const auto encrypted_x = protocol.encrypt(x);
  const auto encrypted_y = protocol.encrypt(y);
  const auto reveal = [&](const mpz_class& value, ProtocolMetrics& metrics) {
    return protocol.decryptForTesting(value, &metrics);
  };
  run("Encrypt", "public", [&](ProtocolMetrics&) {
    return protocol.encrypt(x) > 0;
  });
  run("SADD", "public", [&](ProtocolMetrics&) {
    return protocol.add(encrypted_x, encrypted_y) > 0;
  });
  run("ScalarMul", "public", [&](ProtocolMetrics&) {
    return protocol.scalarMultiply(encrypted_x, 19) > 0;
  });
  run("Decrypt", "threshold", [&](ProtocolMetrics& metrics) {
    return reveal(encrypted_x, metrics) == x;
  });
  run("SMUL", "soci-plus-masked-threshold", [&](ProtocolMetrics& metrics) {
    return reveal(protocol.secureMultiply(encrypted_x, encrypted_y, &metrics),
                  metrics) == x * y;
  });
  run("SCMP", "soci-plus-masked-threshold", [&](ProtocolMetrics& metrics) {
    return reveal(protocol.greaterThan(encrypted_x, encrypted_y, &metrics),
                  metrics) == 1 &&
           reveal(protocol.greaterThan(encrypted_x, encrypted_x, &metrics),
                  metrics) == 0;
  });
  run("SABS", "soci-plus-composed", [&](ProtocolMetrics& metrics) {
    const auto negative = protocol.encrypt(-x);
    const auto sign = protocol.greaterThan(protocol.encrypt(0), negative,
                                           &metrics);
    const auto factor = protocol.add(protocol.encrypt(1),
                                     protocol.scalarMultiply(sign, -2));
    return reveal(protocol.secureMultiply(factor, negative, &metrics),
                  metrics) == x;
  });
  run("SDIV", "soci-plus-composed", [&](ProtocolMetrics& metrics) {
    auto dividend = encrypted_x;
    auto quotient = protocol.encrypt(0);
    const auto one = protocol.encrypt(1);
    for (unsigned step = 16; step-- > 0;) {
      const auto shifted =
          protocol.scalarMultiply(encrypted_y, mpz_class(1) << step);
      const auto less = protocol.greaterThan(shifted, dividend, &metrics);
      const auto take = protocol.add(one, protocol.scalarMultiply(less, -1));
      quotient = protocol.add(
          quotient,
          protocol.scalarMultiply(take, mpz_class(1) << step));
      dividend = protocol.add(
          dividend,
          protocol.scalarMultiply(
              protocol.secureMultiply(take, shifted, &metrics), -1));
    }
    return reveal(quotient, metrics) == x / y &&
           reveal(dividend, metrics) == x % y;
  });

  std::cout << "{\n  \"mode\":\"" << soci::protocol::thresholdModeName(mode)
            << "\",\"architecture\":\"CP/CSP dual process\","
               "\"security_bits\":128,\"modulus_bits\":"
            << mpz_sizeinbase(protocol.modulus().get_mpz_t(), 2)
            << ",\"warmup\":" << warmup << ",\"metrics\":[\n";
  for (std::size_t i = 0; i < all.size(); ++i) {
    printSamples(all[i]);
    std::cout << (i + 1 == all.size() ? "\n" : ",\n");
  }
  std::cout << "  ]\n}\n";
  protocol.requestServerShutdown();
  return 0;
}
}  // namespace

int main(int argc, char** argv) {
  try {
    const auto mode = configuredMode();
    if (argc >= 4 && std::string(argv[1]) == "provision")
      return soci::protocol::provisionThresholdKeys(
          argv[2], argv[3], argc > 4 ? std::stoul(argv[4]) : 3072, mode);
    if (argc >= 5 && std::string(argv[1]) == "csp")
      return soci::protocol::runThresholdCsp(argv[2], argv[3],
                                             std::stoi(argv[4]), mode);
    if (argc >= 7 && std::string(argv[1]) == "benchmark")
      return benchmark(argv[2], argv[3], argv[4], std::stoi(argv[5]),
                       std::stoi(argv[6]),
                       argc > 7 ? std::stoi(argv[7]) : 30, mode);
    std::cerr << "usage: soci_threshold_runtime provision ENCLAVE DIR [BITS] | "
                 "csp ENCLAVE DIR PORT | benchmark ENCLAVE DIR HOST PORT "
                 "WARMUP [SAMPLES]\n";
    return 2;
  } catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
