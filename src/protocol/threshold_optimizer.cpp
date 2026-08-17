#include "soci/threshold_optimizer.hpp"

#include "protocol/threshold_protocol.hpp"

#include <stdexcept>
#include <utility>

namespace soci::optimization {

class ThresholdConfidentialRuntime::Impl {
 public:
  Impl(ThresholdConfidentialConfig config,
       secure::PredicateAuthorizer& authorizer)
      : protocol_(
            checkedPath(config.cp_enclave_path, "cp_enclave_path"),
            checkedPath(config.key_directory, "key_directory"),
            checkedPath(config.csp_host, "csp_host"),
            checkedPort(config.csp_port), protocolMode(config.mode)),
        ops_(protocol_, config.numeric_domain),
        resolver_(protocol_),
        optimizer_({ops_, authorizer, resolver_,
                    std::move(config.solver_config)}) {}

  EncryptedBranchAndBoundResult optimize(
      const EncryptedOptimizationRequest& request) {
    const auto before=protocol_.metrics();
    auto result=optimizer_.optimize(request);
    const auto after=protocol_.metrics();auto& stats=result.stats;
    stats.scmp_logical_items=after.scmp_logical_items-before.scmp_logical_items;
    stats.scmp_dispatches=after.scmp_dispatches-before.scmp_dispatches;
    stats.smul_logical_items=after.smul_logical_items-before.smul_logical_items;
    stats.smul_dispatches=after.smul_dispatches-before.smul_dispatches;
    stats.cp_ecalls=after.cp_ecalls-before.cp_ecalls;
    stats.csp_ecalls=after.csp_ecalls-before.csp_ecalls;
    stats.csp_requests=after.csp_requests-before.csp_requests;
    stats.predicate_reveals=after.predicate_reveals-before.predicate_reveals;
    stats.cp_enclave_seconds=(after.cp_enclave_microseconds-before.cp_enclave_microseconds)/1'000'000.0;
    stats.network_seconds=(after.network_microseconds-before.network_microseconds)/1'000'000.0;
    stats.host_encrypt_seconds=(after.host_encrypt_microseconds-before.host_encrypt_microseconds)/1'000'000.0;
    stats.host_scalar_powm_seconds=(after.host_scalar_powm_microseconds-before.host_scalar_powm_microseconds)/1'000'000.0;
    stats.csp_enclave_seconds=(after.csp_enclave_microseconds-before.csp_enclave_microseconds)/1'000'000.0;
    stats.host_encrypt_calls=after.host_encrypt_calls-before.host_encrypt_calls;
    stats.host_scalar_powm_calls=after.host_scalar_powm_calls-before.host_scalar_powm_calls;
    return result;
  }

 private:
  static const std::string& checkedPath(const std::string& value,
                                        const char* name) {
    if (value.empty()) throw std::invalid_argument(std::string(name) + " is empty");
    return value;
  }

  static int checkedPort(int value) {
    if (value <= 0 || value > 65535)
      throw std::invalid_argument("csp_port is outside 1..65535");
    return value;
  }

  static protocol::ThresholdMode protocolMode(ThresholdExecutionMode mode) {
    if (mode == ThresholdExecutionMode::sim)
      return protocol::ThresholdMode::sim;
    if (mode == ThresholdExecutionMode::hw)
      return protocol::ThresholdMode::hw;
    throw std::invalid_argument("invalid ThresholdExecutionMode");
  }

  protocol::ThresholdProtocolClient protocol_;
  protocol::ThresholdSecureOps ops_;
  protocol::ThresholdPredicateBitResolver resolver_;
  ConfidentialOptimizer optimizer_;
};

ThresholdConfidentialRuntime::ThresholdConfidentialRuntime(
    ThresholdConfidentialConfig config,
    secure::PredicateAuthorizer& authorizer)
    : impl_(std::make_unique<Impl>(std::move(config), authorizer)) {}

ThresholdConfidentialRuntime::~ThresholdConfidentialRuntime() = default;
ThresholdConfidentialRuntime::ThresholdConfidentialRuntime(
    ThresholdConfidentialRuntime&&) noexcept = default;
ThresholdConfidentialRuntime& ThresholdConfidentialRuntime::operator=(
    ThresholdConfidentialRuntime&&) noexcept = default;

EncryptedBranchAndBoundResult ThresholdConfidentialRuntime::optimize(
    const EncryptedOptimizationRequest& request) {
  if (!impl_) throw std::logic_error("moved-from ThresholdConfidentialRuntime");
  return impl_->optimize(request);
}

}  // namespace soci::optimization
