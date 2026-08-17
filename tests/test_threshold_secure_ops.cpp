#include "protocol/threshold_protocol.hpp"
#include "soci/threshold_optimizer.hpp"

#include <arpa/inet.h>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <netinet/in.h>
#include <signal.h>
#include <stdexcept>
#include <sys/socket.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

namespace {

int unusedPort() {
  const int fd = socket(AF_INET, SOCK_STREAM, 0);
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  address.sin_port = 0;
  if (bind(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)))
    throw std::runtime_error("test port bind failed");
  socklen_t size = sizeof(address);
  getsockname(fd, reinterpret_cast<sockaddr*>(&address), &size);
  const int port = ntohs(address.sin_port);
  close(fd);
  return port;
}

void require(bool condition, const char* message) {
  if (!condition) throw std::runtime_error(message);
}

class IntegrationAuthorizer final
    : public soci::secure::PredicateAuthorizer {
 public:
  std::uint64_t calls{};
  bool authorize(const soci::secure::PredicateContext& context) override {
    ++calls;
    return (context.session_id == "threshold-sim" ||
            context.session_id == "threshold-facade" ||
            context.session_id == "threshold-lagrangian") &&
           !context.operation_id.empty() &&
           context.node_id.rfind("node-", 0) == 0;
  }
};

}  // namespace

int main(int argc, char** argv) {
  if (argc != 6) return 2;
  const auto mode = std::string(argv[4]) == "SIM"
                        ? soci::protocol::ThresholdMode::sim
                        : soci::protocol::ThresholdMode::hw;
  const auto directory = std::filesystem::temp_directory_path() /
                         ("soci-threshold-ops-" + std::to_string(getpid()));
  std::filesystem::create_directories(directory);
  pid_t server = -1;
  const char* stage = "provision";
  try {
    soci::protocol::provisionThresholdKeys(argv[1], directory.string(), 3072,
                                           mode);
    const int port = unusedPort();
    server = fork();
    if (server == 0) {
      const auto port_string = std::to_string(port);
      setenv("SOCI_SGX_MODE", argv[4], 1);
      execl(argv[5], argv[5], "csp", argv[3], directory.c_str(),
            port_string.c_str(), static_cast<char*>(nullptr));
      _exit(127);
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(250));
    stage = "connect";
    soci::protocol::ThresholdProtocolClient protocol(
        argv[2], directory.string(), "127.0.0.1", port, mode);
    const soci::secure::NumericDomain domain{1'000'000, 100, 32, 48, 64, 64};
    soci::protocol::ThresholdSecureOps ops(protocol, domain);
    IntegrationAuthorizer authorizer;
    soci::protocol::ThresholdPredicateBitResolver predicate_resolver(protocol);
    soci::secure::PredicateEngine predicate_engine(ops, authorizer,
                                                    predicate_resolver);
    std::uint64_t predicate_sequence = 0;
    bool rejected = false;
    try {
      soci::secure::Ciphertext raw{{1, 2, 3}};
      (void)ops.add(raw, ops.encryptConstant(1));
    } catch (const std::invalid_argument&) {
      rejected = true;
    }
    require(rejected, "raw ciphertext was accepted");
    const auto number = [&](std::int64_t value) {
      return ops.encryptConstant(value);
    };
    const auto reveal = [&](const soci::secure::Ciphertext& value) {
      require(value.bytes.size() >= 12, "short canonical ciphertext");
      require(std::memcmp(value.bytes.data(), "SOCI", 4) == 0,
              "bad canonical ciphertext magic");
      require(value.bytes[4] == 1 && value.bytes[5] == 1,
              "bad canonical ciphertext version/type");
      mpz_class raw;
      mpz_import(raw.get_mpz_t(), value.bytes.size() - 12, 1, 1, 1, 0,
                 value.bytes.data() + 12);
      return protocol.decryptForTesting(raw);
    };
    const auto predicateContext = [&](soci::secure::PredicateType type) {
      return soci::secure::PredicateContext{
          "threshold-sim", "predicate-" + std::to_string(predicate_sequence),
          type,
          3, "node-7"};
    };

    stage = "add";
    require(reveal(ops.add(number(5), number(3))) == 8, "add failed");
    stage = "negative encrypt";
    require(reveal(number(-5)) == -5, "negative encrypt failed");
    stage = "scalarMul";
    require(reveal(ops.scalarMul(number(5), -3)) == -15,
            "scalarMul failed");
    stage = "sub";
    require(reveal(ops.sub(number(3), number(5))) == -2, "sub failed");
    stage = "secureMul";
    require(reveal(ops.secureMul(number(5), number(3))) == 15,
            "positive secureMul failed");
    stage = "negative secureMul";
    require(reveal(ops.secureMul(number(-5), number(3))) == -15,
            "negative secureMul failed");
    stage = "parallel batch encryption independence";
    std::vector<std::pair<soci::secure::Ciphertext,
                          soci::secure::Ciphertext>> repeated_products;
    for(std::size_t i=0;i<8;++i)
      repeated_products.emplace_back(number(5),number(3));
    const auto independently_encrypted=ops.secureMulBatch(repeated_products);
    require(independently_encrypted.size()==repeated_products.size(),
            "parallel SMUL batch size changed");
    for(std::size_t i=0;i<independently_encrypted.size();++i) {
      require(reveal(independently_encrypted[i])==15,
              "parallel SMUL encryption changed plaintext");
      for(std::size_t j=0;j<i;++j)
        require(independently_encrypted[i].bytes!=
                    independently_encrypted[j].bytes,
                "parallel Paillier encryption reused a randomizer");
    }
    stage = "semantic predicates";
    const auto predicate_metrics_before = protocol.metrics();
    ++predicate_sequence;
    require(predicate_engine.pruneNode(
                predicateContext(soci::secure::PredicateType::prune_node),
                {number(-1), number(5), false, {}}),
            "ratio prune failed");
    ++predicate_sequence;
    require(!predicate_engine.pruneNode(
                predicateContext(soci::secure::PredicateType::prune_node),
                {number(0), number(10), true, number(10)}),
            "equal cost pruned");
    ++predicate_sequence;
    require(predicate_engine.acceptCandidate(
                predicateContext(
                    soci::secure::PredicateType::accept_candidate),
                {number(0), number(1), number(10), number(5), true,
                 number(10), number(6)}),
            "equal-cost better-c12 candidate rejected");
    const auto predicate_metrics_after = protocol.metrics();
    require(predicate_metrics_after.logical_items -
                predicate_metrics_before.logical_items == 8,
            "predicate batching changed SCMP/SMUL logical call count");
    require(predicate_metrics_after.cp_ecalls -
                predicate_metrics_before.cp_ecalls == 3 &&
                predicate_metrics_after.csp_requests -
                predicate_metrics_before.csp_requests == 6 &&
                predicate_metrics_after.csp_ecalls -
                predicate_metrics_before.csp_ecalls == 3 &&
                predicate_metrics_after.scmp_logical_items -
                predicate_metrics_before.scmp_logical_items == 8 &&
                predicate_metrics_after.scmp_dispatches -
                predicate_metrics_before.scmp_dispatches == 3 &&
                predicate_metrics_after.smul_logical_items -
                predicate_metrics_before.smul_logical_items == 0 &&
                predicate_metrics_after.smul_dispatches -
                predicate_metrics_before.smul_dispatches == 0 &&
                predicate_metrics_after.secure_bit_and_items-
                predicate_metrics_before.secure_bit_and_items == 4 &&
                predicate_metrics_after.predicate_reveals -
                predicate_metrics_before.predicate_reveals == 3,
            "predicate batching did not reduce ECALL/request dispatches");
    stage = "fused predicate replay";
    ++predicate_sequence;
    const auto fused_replay =
        predicateContext(soci::secure::PredicateType::prune_node);
    require(predicate_engine.pruneNode(
                fused_replay,{number(-1),number(0),false,{}}),
            "initial fused replay predicate failed");
    rejected=false;
    try {
      (void)predicate_engine.pruneNode(
          fused_replay,{number(-1),number(0),false,{}});
    } catch(const soci::secure::PredicateError&) { rejected=true; }
    require(rejected,"fused predicate replay was accepted");
    stage = "K=16 prune batch";
    std::vector<soci::secure::Ciphertext> k16_bounds;
    for(std::size_t i=0;i<16;++i)k16_bounds.push_back(number(9));
    const auto k16_before=protocol.metrics();++predicate_sequence;
    require(!predicate_engine.pruneNode(
                predicateContext(soci::secure::PredicateType::prune_node),
                {number(0),std::move(k16_bounds),true,number(10)}),
            "K=16 equal/lower bounds pruned");
    const auto k16_after=protocol.metrics();
    require(k16_after.scmp_logical_items-k16_before.scmp_logical_items==17&&
                k16_after.scmp_dispatches-k16_before.scmp_dispatches==1,
            "K=16 PRUNE was not one 17-item SCMP batch");
    stage = "composite operations";
    const auto yes = ops.greaterThan(number(5), number(3));
    const auto no = ops.greaterThan(number(3), number(5));
    require(reveal(ops.select(yes, number(11), number(22))) == 11,
            "select failed");
    require(reveal(ops.min(number(9), number(-2))) == -2, "min failed");
    require(reveal(ops.max(number(9), number(-2))) == 9, "max failed");
    // Exercise signed SMUL operands close to the mask boundary.  This value is
    // 2^126 - 2^63, so both signs remain strictly inside |x| < 2^127.
    stage = "positive boundary SMUL";
    const auto power_62 =
        ops.scalarMul(number(1), std::int64_t{1} << 62);
    const auto almost_power_126 = ops.add(
        ops.scalarMul(power_62, INT64_MAX),
        ops.scalarMul(power_62, INT64_MAX));
    const mpz_class boundary_value =
        (mpz_class(1) << 126) - (mpz_class(1) << 63);
    require(reveal(almost_power_126) == boundary_value,
            "positive boundary construction failed");
    require(reveal(ops.secureMul(almost_power_126, number(1))) ==
                boundary_value,
            "positive boundary SMUL failed");
    stage = "negative boundary SMUL";
    const auto negative_boundary = ops.scalarMul(almost_power_126, -1);
    require(reveal(ops.secureMul(negative_boundary, number(1))) ==
                -boundary_value,
            "negative boundary SMUL failed");
    stage = "boundary comparison";
    ++predicate_sequence;
    require(predicate_engine.pruneNode(
                predicateContext(soci::secure::PredicateType::prune_node),
                {negative_boundary, almost_power_126, false, {}}),
            "boundary predicate failed");

    const auto facade_cost = number(7);
    const std::array<std::array<std::int64_t, 3>, 5> lagrangian_plain{{
        {{18, 18, 12}}, {{1, 7, 1}}, {{17, 4, 9}}, {{13, 4, 17}},
        {{3, 18, 9}},
    }};
    std::vector<soci::optimization::EncryptedCostRow> lagrangian_costs;
    for (const auto& plain_row : lagrangian_plain) {
      soci::optimization::EncryptedCostRow encrypted_row;
      for (std::size_t method = 0; method < 3; ++method)
        encrypted_row.methods[method] = number(plain_row[method]);
      lagrangian_costs.push_back(std::move(encrypted_row));
    }

    rejected = false;
    try {
      soci::protocol::ThresholdSecureOps invalid(protocol, {});
    } catch (const std::invalid_argument&) {
      rejected = true;
    }
    require(rejected, "empty NumericDomain was accepted");
    rejected = false;
    try {
      auto underdeclared = domain;
      underdeclared.max_total_bits = 38;  // 32 + ceilLog2(100) == 39.
      soci::protocol::ThresholdSecureOps invalid(protocol, underdeclared);
    } catch (const std::invalid_argument&) {
      rejected = true;
    }
    require(rejected, "underdeclared total bits were accepted");
    rejected = false;
    try {
      auto underdeclared = domain;
      underdeclared.max_linear_bits = 59;  // 39 + ceilLog2(1e6) + 1 == 60.
      soci::protocol::ThresholdSecureOps invalid(protocol, underdeclared);
    } catch (const std::invalid_argument&) {
      rejected = true;
    }
    require(rejected, "underdeclared linear bits were accepted");
    rejected = false;
    try {
      auto underdeclared = domain;
      underdeclared.compare_operand_bits = 59;
      soci::protocol::ThresholdSecureOps invalid(protocol, underdeclared);
    } catch (const std::invalid_argument&) {
      rejected = true;
    }
    require(rejected, "underdeclared compare bits were accepted");
    rejected = false;
    try {
      auto excessive = domain;
      excessive.max_linear_bits = 129;
      soci::protocol::ThresholdSecureOps invalid(protocol, excessive);
    } catch (const std::invalid_argument&) {
      rejected = true;
    }
    require(rejected, "excessive NumericDomain was accepted");

    protocol.requestServerShutdown();
    int status = 0;
    waitpid(server, &status, 0);
    server = -1;
    require(WIFEXITED(status) && WEXITSTATUS(status) == 0,
            "CSP did not shut down cleanly");

    stage = "ThresholdConfidentialRuntime end-to-end";
    const int facade_port = unusedPort();
    server = fork();
    if (server == 0) {
      const auto port_string = std::to_string(facade_port);
      setenv("SOCI_SGX_MODE", argv[4], 1);
      execl(argv[5], argv[5], "csp", argv[3], directory.c_str(),
            port_string.c_str(), static_cast<char*>(nullptr));
      _exit(127);
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(250));

    soci::optimization::EncryptedOptimizationRequest request;
    request.session_id = "threshold-facade";
    request.threshold_scaled = 0;
    soci::optimization::EncryptedCostRow row;
    row.methods[2] = facade_cost;
    request.costs.push_back(std::move(row));
    soci::optimization::EncryptedBranchAndBoundResult optimized;
    soci::optimization::EncryptedBranchAndBoundResult lagrangian_optimized;
    {
      soci::optimization::ThresholdConfidentialConfig config{
          argv[2], directory.string(), "127.0.0.1", facade_port,
          mode == soci::protocol::ThresholdMode::sim
              ? soci::optimization::ThresholdExecutionMode::sim
              : soci::optimization::ThresholdExecutionMode::hw,
          domain};
      config.solver_config.cost_bound =
          soci::optimization::EncryptedCostBound::lagrangian;
      config.solver_config.lagrangian_grid.denominator = 1;
      config.solver_config.lagrangian_grid.requested_size = 3;
      soci::optimization::ThresholdConfidentialRuntime confidential_runtime(
          std::move(config), authorizer);
      auto authorizer_before = authorizer.calls;
      optimized = confidential_runtime.optimize(request);
      require(authorizer.calls - authorizer_before ==
                  optimized.stats.prune_predicates +
                      optimized.stats.accept_predicates,
              "threshold facade revealed outside PRUNE/ACCEPT");

      soci::optimization::EncryptedOptimizationRequest lagrangian_request;
      lagrangian_request.session_id = "threshold-lagrangian";
      lagrangian_request.threshold_scaled = 500'000;
      lagrangian_request.costs = std::move(lagrangian_costs);
      authorizer_before = authorizer.calls;
      lagrangian_optimized =
          confidential_runtime.optimize(lagrangian_request);
      require(authorizer.calls - authorizer_before ==
                  lagrangian_optimized.stats.prune_predicates +
                      lagrangian_optimized.stats.accept_predicates,
              "multi-LB solve revealed outside PRUNE/ACCEPT");
    }
    require(optimized.feasible, "Threshold facade found no solution");
    require(optimized.solution == std::vector<std::uint8_t>{3},
            "Threshold facade selected the wrong method");
    require(lagrangian_optimized.feasible,
            "multi-LB threshold facade found no solution");
    require(lagrangian_optimized.solution ==
                std::vector<std::uint8_t>({3, 1, 2, 2, 1}),
            "multi-LB threshold facade selected the wrong methods");
    require(lagrangian_optimized.stats.multi_bound_prune_nodes > 0 &&
                lagrangian_optimized.stats.objective_bound_comparisons >= 3,
            "SIM E2E did not exercise incumbent multi-LB pruning");

    soci::protocol::ThresholdProtocolClient verifier(
        argv[2], directory.string(), "127.0.0.1", facade_port, mode);
    const auto verify = [&](const soci::secure::Ciphertext& value) {
      mpz_class raw;
      mpz_import(raw.get_mpz_t(), value.bytes.size() - 12, 1, 1, 1, 0,
                 value.bytes.data() + 12);
      return verifier.decryptForTesting(raw);
    };
    require(verify(optimized.total_cost) == 7 && verify(optimized.c12) == 0 &&
                verify(optimized.c3) == 7,
            "Threshold facade returned incorrect encrypted aggregates");
    require(verify(lagrangian_optimized.total_cost) == 24 &&
                verify(lagrangian_optimized.c12) == 12 &&
                verify(lagrangian_optimized.c3) == 12,
            "multi-LB facade returned incorrect encrypted aggregates");
    verifier.requestServerShutdown();
    waitpid(server, &status, 0);
    server = -1;
    require(WIFEXITED(status) && WEXITSTATUS(status) == 0,
            "facade CSP did not shut down cleanly");
    std::filesystem::remove_all(directory);
    std::cout << "ThresholdSecureOps " << argv[4]
              << " integration tests passed\n";
    return 0;
  } catch (const std::exception& error) {
    if (server > 0) {
      int status = 0;
      if (waitpid(server, &status, WNOHANG) == 0) {
        kill(server, SIGTERM);
        waitpid(server, &status, 0);
      }
      if (WIFSIGNALED(status))
        std::cerr << "CSP terminated by signal " << WTERMSIG(status) << '\n';
      else if (WIFEXITED(status))
        std::cerr << "CSP exited with status " << WEXITSTATUS(status) << '\n';
    }
    std::filesystem::remove_all(directory);
    std::cerr << "stage " << stage << ": " << error.what() << '\n';
    return 1;
  }
}
