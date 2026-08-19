#include "protocol/threshold_protocol.hpp"
#include "soci/confidential_scalable_optimizer.hpp"
#include "soci/scalable_optimizer.hpp"

#include <arpa/inet.h>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <netinet/in.h>
#include <stdexcept>
#include <sys/socket.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

namespace {

void require(bool condition, const char* message) {
  if (!condition) throw std::runtime_error(message);
}

int unusedPort() {
  const int fd = socket(AF_INET, SOCK_STREAM, 0);
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  address.sin_port = 0;
  require(bind(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0,
          "port bind failed");
  socklen_t length = sizeof(address);
  getsockname(fd, reinterpret_cast<sockaddr*>(&address), &length);
  const int port = ntohs(address.sin_port);
  close(fd);
  return port;
}

using Row = std::array<std::optional<std::int64_t>, 3>;

class LocalSecureOps final : public soci::secure::SecureOps {
 public:
  soci::secure::Ciphertext encryptConstant(std::int64_t value) override {
    soci::secure::Ciphertext result;
    result.bytes.resize(sizeof(value));
    std::memcpy(result.bytes.data(), &value, sizeof(value));
    return result;
  }
  soci::secure::Ciphertext add(const soci::secure::Ciphertext& a,
                               const soci::secure::Ciphertext& b) override {
    return encryptConstant(value(a) + value(b));
  }
  soci::secure::Ciphertext scalarMul(const soci::secure::Ciphertext& a,
                                     std::int64_t scalar) override {
    return encryptConstant(value(a) * scalar);
  }
  soci::secure::Ciphertext secureMul(const soci::secure::Ciphertext& a,
                                     const soci::secure::Ciphertext& b) override {
    return encryptConstant(value(a) * value(b));
  }
  soci::secure::EncryptedBit greaterThan(
      const soci::secure::Ciphertext& a,
      const soci::secure::Ciphertext& b) override {
    return encryptedBit(encryptConstant(value(a) > value(b)));
  }
  const soci::secure::NumericDomain& domain() const noexcept override {
    return domain_;
  }
  std::int64_t value(const soci::secure::Ciphertext& input) const {
    require(input.bytes.size() == sizeof(std::int64_t), "bad local ciphertext");
    std::int64_t result{};
    std::memcpy(&result, input.bytes.data(), sizeof(result));
    return result;
  }

 private:
  soci::secure::NumericDomain domain_{100, 64, 8, 16, 28, 56};
};

class ThresholdHarness {
 public:
  ThresholdHarness(const char* provisioning, const char* cp, const char* csp,
                   const char* mode, const char* runtime)
      : directory_(std::filesystem::temp_directory_path() /
                   ("soci-pega-" + std::to_string(getpid()))),
        mode_(std::string(mode) == "SIM" ? soci::protocol::ThresholdMode::sim
                                          : soci::protocol::ThresholdMode::hw),
        cp_(cp), csp_(csp), runtime_(runtime) {
    std::filesystem::create_directories(directory_);
    soci::protocol::provisionThresholdKeys(provisioning, directory_.string(),
                                           3072, mode_);
    const int port = unusedPort();
    server_ = fork();
    if (server_ == 0) {
      const auto port_text = std::to_string(port);
      setenv("SOCI_SGX_MODE", mode, 1);
      execl(runtime_.c_str(), runtime_.c_str(), "csp", csp_.c_str(),
            directory_.c_str(), port_text.c_str(), static_cast<char*>(nullptr));
      _exit(127);
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(250));
    protocol_ = std::make_unique<soci::protocol::ThresholdProtocolClient>(
        cp_, directory_.string(), "127.0.0.1", port, mode_);
    ops_ = std::make_unique<soci::protocol::ThresholdSecureOps>(
        *protocol_, soci::secure::NumericDomain{100, 16, 8, 12, 24, 48});
  }

  ~ThresholdHarness() {
    if (protocol_) {
      try { protocol_->requestServerShutdown(); } catch (...) {}
    }
    if (server_ > 0) {
      int status{};
      waitpid(server_, &status, 0);
    }
    std::filesystem::remove_all(directory_);
  }

  soci::optimization::ConfidentialScalableOptimizationResult solve(
      const std::vector<Row>& plain, std::int64_t threshold) {
    soci::optimization::EncryptedOptimizationRequest request;
    request.threshold_scaled = threshold;
    request.session_id = "pega-" + std::to_string(++session_);
    for (const auto& source : plain) {
      soci::optimization::EncryptedCostRow encrypted;
      for (std::size_t method = 0; method < 3; ++method)
        if (source[method])
          encrypted.methods[method] = ops_->encryptConstant(*source[method]);
      request.costs.push_back(std::move(encrypted));
    }
    soci::optimization::ConfidentialScalableOptimizerConfig config;
    config.population = 2;
    config.generations = 1;
    config.elitism = 1;
    config.tournament_size = 1;
    config.repair_rounds = 1;
    config.crossover_rate = 0;
    config.mutation_rate = 0;
    config.seed = 123;
    return soci::optimization::ConfidentialScalableOptimizer(*ops_, config)
        .optimize(request);
  }

  std::int64_t decrypt(const soci::secure::Ciphertext& value) const {
    require(value.bytes.size() >= 12, "short canonical ciphertext");
    mpz_class raw;
    mpz_import(raw.get_mpz_t(), value.bytes.size() - 12, 1, 1, 1, 0,
               value.bytes.data() + 12);
    return protocol_->decryptForTesting(raw).get_si();
  }

 private:
  std::filesystem::path directory_;
  soci::protocol::ThresholdMode mode_;
  std::string cp_;
  std::string csp_;
  std::string runtime_;
  pid_t server_{-1};
  std::unique_ptr<soci::protocol::ThresholdProtocolClient> protocol_;
  std::unique_ptr<soci::protocol::ThresholdSecureOps> ops_;
  std::uint64_t session_{};
};

void assertSolution(ThresholdHarness& harness,
                    const soci::optimization::ConfidentialScalableOptimizationResult& result,
                    const std::vector<std::uint8_t>& expected) {
  require(harness.decrypt(result.linear) >= 0 && harness.decrypt(result.c3) > 0 &&
              harness.decrypt(result.total_cost) > 0,
          "expected feasible result");
  require(result.chromosome.size() == expected.size(), "wrong chromosome length");
  for (std::size_t row = 0; row < expected.size(); ++row)
    for (std::size_t method = 0; method < 3; ++method)
      require(harness.decrypt(result.chromosome[row][method]) ==
                  (method == expected[row] ? 1 : 0),
              "unexpected encrypted one-hot chromosome");
  require(result.stats.run.add > 0 && result.stats.run.scalar_mul > 0 &&
              result.stats.run.secure_mul > 0 &&
              result.stats.run.secure_compare > 0 &&
              result.stats.run.secure_select > 0,
          "missing PEGA operation profile");
  require(result.stats.extrapolated_256x1000.secure_mul >=
              result.stats.run.secure_mul,
          "missing 256x1000 extrapolation");
}

std::vector<std::uint8_t> localSolution(const std::vector<Row>& plain,
                                        std::int64_t threshold = 50,
                                        std::size_t population = 2,
                                        std::size_t generations = 1,
                                        std::size_t elitism = 1,
                                        std::size_t tournament = 1,
                                        double crossover = 0.0,
                                        double mutation = 0.0) {
  LocalSecureOps ops;
  soci::optimization::EncryptedOptimizationRequest request;
  request.threshold_scaled = threshold;
  request.session_id = "local-differential";
  soci::optimization::CostMatrix reference;
  for (const auto& source : plain) {
    soci::optimization::EncryptedCostRow encrypted;
    soci::optimization::CostRow reference_row;
    for (std::size_t method = 0; method < 3; ++method) {
      if (!source[method]) continue;
      encrypted.methods[method] = ops.encryptConstant(*source[method]);
      reference_row[method] = std::to_string(*source[method]);
    }
    request.costs.push_back(std::move(encrypted));
    reference.push_back(std::move(reference_row));
  }
  soci::optimization::ConfidentialScalableOptimizerConfig encrypted_config;
  encrypted_config.population = population;
  encrypted_config.generations = generations;
  encrypted_config.elitism = elitism;
  encrypted_config.tournament_size = tournament;
  encrypted_config.repair_rounds = plain.size() * 3;
  encrypted_config.crossover_rate = crossover;
  encrypted_config.mutation_rate = mutation;
  encrypted_config.seed = 123;
  const auto encrypted =
      soci::optimization::ConfidentialScalableOptimizer(ops, encrypted_config)
          .optimize(request);
  soci::optimization::GeneticSolverConfig plain_config;
  plain_config.population = encrypted_config.population;
  plain_config.generations = encrypted_config.generations;
  plain_config.elitism = encrypted_config.elitism;
  plain_config.tournament_size = encrypted_config.tournament_size;
  plain_config.crossover_rate = encrypted_config.crossover_rate;
  plain_config.mutation_rate = encrypted_config.mutation_rate;
  plain_config.seed = encrypted_config.seed;
  const auto expected = soci::optimization::ScalableOptimizer(plain_config)
                            .optimize(reference,
                                      std::to_string(threshold / 100.0));
  std::vector<std::uint8_t> solution;
  for (std::size_t row = 0; row < encrypted.chromosome.size(); ++row) {
    std::uint8_t selected = 0;
    std::int64_t sum = 0;
    for (std::size_t method = 0; method < 3; ++method) {
      const auto bit = ops.value(encrypted.chromosome[row][method]);
      sum += bit;
      if (bit == 1) selected = static_cast<std::uint8_t>(method + 1);
    }
    require(sum == 1, "local result is not one-hot");
    solution.push_back(selected);
  }
  require(std::vector<int>(solution.begin(), solution.end()) == expected.solution,
          "plaintext/encrypted GA solution mismatch");
  require(ops.value(encrypted.total_cost) ==
              static_cast<std::int64_t>(expected.total_cost),
          "plaintext/encrypted GA total mismatch");
  std::cout << "PEGA_LOCAL rows=" << plain.size()
            << " add=" << encrypted.stats.run.add
            << " scalar=" << encrypted.stats.run.scalar_mul
            << " smul=" << encrypted.stats.run.secure_mul
            << " scmp=" << encrypted.stats.run.secure_compare
            << " select=" << encrypted.stats.run.secure_select << '\n';
  return solution;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc != 6) return 2;
  try {
    // Fast deterministic semantic differential coverage uses the exact same
    // optimizer and SecureOps interface without protocol latency.
    // Deterministic differential inputs of 3, 5, and 10 rows.  Extra rows
    // have a single public method, making the expected encrypted chromosome
    // independent of the public random schedule.
    std::vector<Row> base{{Row{10, 11, 1}, Row{10, std::nullopt, 1},
                           Row{std::nullopt, 8, 20}}};
    require(localSolution(base).size() == 3, "3-row differential failed");
    base.push_back(Row{std::nullopt, 1, std::nullopt});
    base.push_back(Row{std::nullopt, 1, std::nullopt});
    require(localSolution(base).size() == 5, "5-row differential failed");
    while (base.size() < 10) base.push_back(Row{std::nullopt, 1, std::nullopt});
    require(localSolution(base).size() == 10, "10-row differential failed");

    // Cheapest starts infeasible here; one fixed repair scan must switch a
    // row to method3 without resolving the feasibility bit.
    require(localSolution({Row{10, std::nullopt, 1},
                           Row{10, std::nullopt, 1},
                           Row{10, std::nullopt, 1}}, 80).size() == 3,
            "repair differential failed");
    // Missing methods and exact ratio/lexical ties retain the lower method.
    require(localSolution({Row{1, 1, 3}, Row{3, 3, 1}}).size() == 2,
            "ratio/lex differential failed");
    bool no_feasible = false;
    try {
      (void)localSolution({Row{1, std::nullopt, std::nullopt},
                           Row{2, std::nullopt, std::nullopt}});
    } catch (const soci::optimization::OptimizationError& error) {
      no_feasible = error.status() == soci::optimization::Status::no_feasible_solution;
    }
    require(no_feasible, "plaintext no-feasible semantic was not preserved");
    std::vector<Row> trend(30, Row{std::nullopt, 1, 2});
    require(localSolution(trend).size() == 30, "30-row differential failed");
    require(localSolution({Row{2, 4, 3}, Row{5, 1, 4}, Row{3, 6, 2},
                           Row{4, 2, 5}, Row{1, 3, 6}}, 50, 8, 5, 2, 3,
                           0.6, 0.2).size() == 5,
            "normal GA differential failed");

    // One real threshold run proves the existing CP/CSP SIM flow.  Keeping
    // the remaining matrix differential local prevents an unbatched MVP test
    // from multiplying protocol round trips by every edge case.
    ThresholdHarness harness(argv[1], argv[2], argv[3], argv[4], argv[5]);
    const auto threshold_result = harness.solve(
        {Row{10, 11, 1}, Row{10, std::nullopt, 1},
         Row{std::nullopt, 8, 20}}, 50);
    assertSolution(harness, threshold_result, {2, 2, 1});
    const auto& counts = threshold_result.stats;
    std::cout << "PEGA_COUNTS run_add=" << counts.run.add
              << " run_scalar_mul=" << counts.run.scalar_mul
              << " run_scmp=" << counts.run.secure_compare
              << " run_smul=" << counts.run.secure_mul
              << " run_select=" << counts.run.secure_select
              << " run_smul_dispatch=" << counts.run.secure_mul_dispatches
              << " run_scmp_dispatch=" << counts.run.secure_compare_dispatches
              << " candidate_add=" << counts.per_candidate.add
              << " candidate_scalar_mul=" << counts.per_candidate.scalar_mul
              << " candidate_scmp=" << counts.per_candidate.secure_compare
              << " candidate_smul=" << counts.per_candidate.secure_mul
              << " candidate_select=" << counts.per_candidate.secure_select
              << " generation_add=" << counts.per_generation.add
              << " generation_scalar_mul=" << counts.per_generation.scalar_mul
              << " generation_scmp=" << counts.per_generation.secure_compare
              << " generation_smul=" << counts.per_generation.secure_mul
              << " generation_select=" << counts.per_generation.secure_select
              << " estimate_add=" << counts.extrapolated_256x1000.add
              << " estimate_scalar_mul="
              << counts.extrapolated_256x1000.scalar_mul
              << " estimate_scmp="
              << counts.extrapolated_256x1000.secure_compare
              << " estimate_smul="
              << counts.extrapolated_256x1000.secure_mul
              << " estimate_select="
              << counts.extrapolated_256x1000.secure_select
              << " estimate410_smul="
              << counts.extrapolated_410x1000.secure_mul
              << " estimate410_scmp="
              << counts.extrapolated_410x1000.secure_compare << '\n';
    std::cout << "confidential scalable optimizer SIM tests passed\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
