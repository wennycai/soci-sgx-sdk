#pragma once
#include <gmpxx.h>
#include <filesystem>
#include <mutex>
#include <string>
#include <vector>
#include "soci/soci.h"
namespace soci::detail {
constexpr uint32_t kMaxObject = 1024*1024;
struct PublicKey { mpz_class n, nsq; };
struct SecretKey { mpz_class lambda, mu; };
struct Key { PublicKey pub; SecretKey sec; soci_key_info_t info{}; };
void keygen(uint32_t, Key&);
mpz_class encrypt(const PublicKey&, const mpz_class&, gmp_randclass&);
mpz_class decrypt(const Key&, const mpz_class&);
std::vector<uint8_t> encode_object(uint8_t, soci_mode_t, const mpz_class&);
mpz_class decode_object(const uint8_t*, size_t, uint8_t, soci_mode_t);
std::vector<uint8_t> encode_public(const Key&);
void save_off_key(const std::filesystem::path&, const Key&);
Key load_off_key(const std::filesystem::path&, soci_mode_t, soci_role_t);
bool valid_id(const std::string&);
}
struct soci_runtime {
  mutable std::mutex mu;
  std::filesystem::path root;
  soci_mode_t mode{SOCI_MODE_OFF};
  std::string error;
  std::unique_ptr<soci::detail::Key> key;
  std::unique_ptr<gmp_randclass> rng;
  bool cp_running{}, csp_running{}, closed{};
};
