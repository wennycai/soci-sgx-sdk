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
    return optimizer_.optimize(request);
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
