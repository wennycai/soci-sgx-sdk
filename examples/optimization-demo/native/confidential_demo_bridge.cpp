#include <jni.h>

#include "soci/encrypted_optimizer.hpp"
#include "soci/soci.hpp"
#include "soci/threshold_optimizer.hpp"

#if SOCI_DEMO_HAS_THRESHOLD
#include "protocol/threshold_protocol.hpp"
#endif

#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
using namespace soci;
using namespace soci::optimization;

void fail(JNIEnv* env, const std::exception& error) {
  env->ThrowNew(env->FindClass("com/soci/sdk/SociException"), error.what());
}
std::string text(JNIEnv* env, jstring value) {
  if (!value) return {};
  const char* chars = env->GetStringUTFChars(value, nullptr);
  std::string out(chars);
  env->ReleaseStringUTFChars(value, chars);
  return out;
}
std::vector<std::uint8_t> bytes(JNIEnv* env, jbyteArray value) {
  std::vector<std::uint8_t> out(env->GetArrayLength(value));
  env->GetByteArrayRegion(value, 0, out.size(),
                          reinterpret_cast<jbyte*>(out.data()));
  return out;
}
jbyteArray byteArray(JNIEnv* env, const std::vector<std::uint8_t>& value) {
  auto out = env->NewByteArray(value.size());
  env->SetByteArrayRegion(out, 0, value.size(),
                         reinterpret_cast<const jbyte*>(value.data()));
  return out;
}

class DemoAuthorizer final : public secure::PredicateAuthorizer {
 public:
  bool authorize(const secure::PredicateContext& context) override {
    return context.session_id.rfind("demo-", 0) == 0 &&
           context.node_id.rfind("node-", 0) == 0;
  }
};

#if !SOCI_DEMO_HAS_THRESHOLD
class OffResolver final : public secure::PredicateBitResolver {
 public:
  explicit OffResolver(Runtime& runtime) : runtime_(runtime) {}
 private:
  bool revealFinalBit(const secure::PredicateContext&,
                      const secure::EncryptedBit& bit) override {
    const auto value = runtime_.decrypt(bit.ciphertext().bytes);
    if (value != "0" && value != "1")
      throw std::runtime_error("predicate did not resolve to a bit");
    return value == "1";
  }
  Runtime& runtime_;
};
#endif

class Bridge {
 public:
  Bridge(std::string mode, const std::string& runtime_dir,
         const std::string& cp, const std::string& keys,
         const std::string& host, int port) : mode_(std::move(mode)) {
#if SOCI_DEMO_HAS_THRESHOLD
    if (mode_ != SOCI_DEMO_MODE)
      throw std::invalid_argument("bridge mode does not match native build");
    threshold_mode_ = mode_ == "SIM"
        ? protocol::ThresholdMode::sim : protocol::ThresholdMode::hw;
    cp_ = cp; keys_ = keys; host_ = host; port_ = port;
    threshold_config_ = ThresholdConfidentialConfig{
        cp, keys, host, port,
        mode_ == "SIM" ? ThresholdExecutionMode::sim
                       : ThresholdExecutionMode::hw,
        domain()};
#else
    if (mode_ != "OFF") throw std::invalid_argument("OFF bridge required");
    runtime_ = std::make_unique<Runtime>(runtime_dir);
    runtime_->create_key("demo", 3072);
#endif
  }

  secure::Ciphertext encrypt(std::int64_t value) {
#if SOCI_DEMO_HAS_THRESHOLD
    protocol::ThresholdProtocolClient protocol(cp_, keys_, host_, port_,
                                               threshold_mode_);
    protocol::ThresholdSecureOps ops(protocol, domain());
    return ops.encryptConstant(value);
#else
    return secure::Ciphertext{runtime_->encrypt(std::to_string(value))};
#endif
  }

  EncryptedBranchAndBoundResult optimize(EncryptedOptimizationRequest request,
                                         EncryptedBranchAndBoundConfig config) {
#if SOCI_DEMO_HAS_THRESHOLD
    threshold_config_.solver_config = std::move(config);
    ThresholdConfidentialRuntime runtime(threshold_config_, authorizer_);
    return runtime.optimize(request);
#else
    secure::RuntimeSecureOps ops(*runtime_, domain());
    OffResolver resolver(*runtime_);
    ConfidentialOptimizer optimizer({ops, authorizer_, resolver,
                                     std::move(config)});
    return optimizer.optimize(request);
#endif
  }
  const std::string& mode() const { return mode_; }

 private:
  static secure::NumericDomain domain() {
    return {1'000'000, 64, 36, 48, 64, 64};
  }
  std::string mode_;
  DemoAuthorizer authorizer_;
#if SOCI_DEMO_HAS_THRESHOLD
  std::string cp_, keys_, host_;
  int port_{};
  protocol::ThresholdMode threshold_mode_{protocol::ThresholdMode::sim};
  ThresholdConfidentialConfig threshold_config_;
#else
  std::unique_ptr<Runtime> runtime_;
#endif
};

jobject resultObject(JNIEnv* env, const EncryptedBranchAndBoundResult& result) {
  jintArray solution = env->NewIntArray(result.solution.size());
  std::vector<jint> methods(result.solution.begin(), result.solution.end());
  env->SetIntArrayRegion(solution, 0, methods.size(), methods.data());
  jclass byte_class = env->FindClass("[B");
  jobjectArray ciphertexts = env->NewObjectArray(4, byte_class, nullptr);
  const secure::Ciphertext values[] = {result.total_cost, result.c12,
                                      result.c3, result.linear};
  for (int i = 0; i < 4; ++i)
    env->SetObjectArrayElement(ciphertexts, i, byteArray(env, values[i].bytes));
  jclass cls = env->FindClass("com/soci/sdk/ConfidentialOptimizationResult");
  jmethodID ctor = env->GetMethodID(cls, "<init>",
      "(Z[I[[BJJJJJJJJJJJJJJJJJJDDDDDDDDDDDDDDDDDD)V");
  const auto& s = result.stats;
  return env->NewObject(cls, ctor, result.feasible ? JNI_TRUE : JNI_FALSE,
      solution, ciphertexts, static_cast<jlong>(s.visited_nodes),
      static_cast<jlong>(s.pruned_nodes), static_cast<jlong>(s.candidate_count),
      static_cast<jlong>(s.prune_predicates),
      static_cast<jlong>(s.accept_predicates),
      static_cast<jlong>(s.scmp_logical_items),static_cast<jlong>(s.scmp_dispatches),
      static_cast<jlong>(s.smul_logical_items),static_cast<jlong>(s.smul_dispatches),
      static_cast<jlong>(s.cp_ecalls),static_cast<jlong>(s.csp_ecalls),
      static_cast<jlong>(s.csp_requests),static_cast<jlong>(s.predicate_reveals),
      static_cast<jlong>(s.secure_bit_and_items),
      static_cast<jlong>(s.predicate_csp_encryptions),
      static_cast<jlong>(s.predicate_final_threshold_decrypts),
      static_cast<jlong>(s.host_encrypt_calls),
      static_cast<jlong>(s.host_scalar_powm_calls),s.host_encrypt_seconds,
      s.host_scalar_powm_seconds,s.cp_enclave_seconds,s.csp_enclave_seconds,
      s.network_seconds,s.csp_request_seconds,s.csp_encrypt_seconds,
      s.csp_parse_serialize_seconds,s.csp_socket_send_seconds,
      s.fused_cp_rsa_private_powm_seconds,
      s.fused_csp_rsa_public_powm_seconds,s.fused_garble_seconds,
      s.fused_circuit_evaluate_seconds,s.fused_f_request_seconds,
      s.fused_g_request_seconds,
      s.preprocessing_seconds,s.search_seconds,s.total_seconds);
}
}  // namespace

extern "C" JNIEXPORT jlong JNICALL
Java_com_soci_sdk_ConfidentialOptimizationDemoBridge_nativeCreate(
    JNIEnv* env, jclass, jstring mode, jstring runtime_dir, jstring cp,
    jstring keys, jstring host, jint port) {
  try {
    return reinterpret_cast<jlong>(new Bridge(
        text(env, mode), text(env, runtime_dir), text(env, cp),
        text(env, keys), text(env, host), port));
  } catch (const std::exception& error) { fail(env, error); return 0; }
}
extern "C" JNIEXPORT void JNICALL
Java_com_soci_sdk_ConfidentialOptimizationDemoBridge_nativeClose(
    JNIEnv*, jclass, jlong handle) { delete reinterpret_cast<Bridge*>(handle); }
extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_soci_sdk_ConfidentialOptimizationDemoBridge_nativeEncrypt(
    JNIEnv* env, jclass, jlong handle, jlong value) {
  try { return byteArray(env, reinterpret_cast<Bridge*>(handle)->encrypt(value).bytes); }
  catch (const std::exception& error) { fail(env, error); return nullptr; }
}
extern "C" JNIEXPORT jobject JNICALL
Java_com_soci_sdk_ConfidentialOptimizationDemoBridge_nativeOptimize(
    JNIEnv* env, jclass, jlong handle, jobjectArray rows, jlong threshold,
    jstring strategy, jint grid_size, jstring session) {
  try {
    EncryptedOptimizationRequest request;
    request.threshold_scaled = threshold;
    request.session_id = text(env, session);
    request.costs.resize(env->GetArrayLength(rows));
    for (jsize i = 0; i < env->GetArrayLength(rows); ++i) {
      auto row = static_cast<jobjectArray>(env->GetObjectArrayElement(rows, i));
      if (!row || env->GetArrayLength(row) != 3)
        throw std::invalid_argument("every encrypted row needs three methods");
      for (jsize j = 0; j < 3; ++j) {
        auto value = static_cast<jbyteArray>(env->GetObjectArrayElement(row, j));
        if (value) {
          request.costs[i].methods[j] = secure::Ciphertext{bytes(env, value)};
          env->DeleteLocalRef(value);
        }
      }
      env->DeleteLocalRef(row);
    }
    EncryptedBranchAndBoundConfig config;
    const auto selected = text(env, strategy);
    if (selected == "lagrangian") {
      config.cost_bound = EncryptedCostBound::lagrangian;
      config.lagrangian_grid.requested_size = grid_size;
    } else if (selected != "current_suffix") {
      throw std::invalid_argument("unknown solver strategy");
    }
    return resultObject(env, reinterpret_cast<Bridge*>(handle)->optimize(
                                 std::move(request), std::move(config)));
  } catch (const std::exception& error) { fail(env, error); return nullptr; }
}
extern "C" JNIEXPORT jstring JNICALL
Java_com_soci_sdk_ConfidentialOptimizationDemoBridge_nativeMode(
    JNIEnv* env, jclass, jlong handle) {
  return env->NewStringUTF(reinterpret_cast<Bridge*>(handle)->mode().c_str());
}
