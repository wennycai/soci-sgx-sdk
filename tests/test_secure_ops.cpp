#include "soci/secure_ops.hpp"

#include <cassert>
#include <filesystem>
#include <iostream>

int main() {
  const auto directory =
      std::filesystem::temp_directory_path() / "soci-secure-ops-test";
  std::filesystem::remove_all(directory);
  soci::Runtime runtime(directory.string());
  runtime.create_key("secure-ops");
  soci::secure::RuntimeSecureOps ops(runtime);

  const auto number = [&](long long value) {
    return ops.encryptConstant(value);
  };
  const auto reveal = [&](const soci::secure::Ciphertext& value) {
    return runtime.decrypt(value.bytes);
  };
  const auto revealBit = [&](const soci::secure::EncryptedBit& value) {
    return reveal(value.ciphertext());
  };

  assert(reveal(ops.add(number(5), number(3))) == "8");
  assert(reveal(ops.sub(number(5), number(3))) == "2");
  assert(reveal(ops.scalarMul(number(5), -3)) == "-15");
  assert(reveal(ops.secureMul(number(-5), number(3))) == "-15");

  assert(revealBit(ops.greaterThan(number(5), number(3))) == "1");
  assert(revealBit(ops.greaterThan(number(3), number(5))) == "0");
  assert(revealBit(ops.greaterThan(number(5), number(5))) == "0");
  assert(revealBit(ops.lessThan(number(3), number(5))) == "1");
  assert(revealBit(ops.greaterEqual(number(5), number(5))) == "1");
  assert(revealBit(ops.lessEqual(number(5), number(5))) == "1");
  assert(revealBit(ops.equal(number(5), number(5))) == "1");
  assert(revealBit(ops.equal(number(5), number(3))) == "0");

  const auto yes = ops.greaterThan(number(5), number(3));
  const auto no = ops.greaterThan(number(3), number(5));
  assert(revealBit(ops.bitNot(yes)) == "0");
  assert(revealBit(ops.bitAnd(yes, no)) == "0");
  assert(revealBit(ops.bitOr(yes, no)) == "1");
  assert(reveal(ops.select(yes, number(11), number(22))) == "11");
  assert(reveal(ops.select(no, number(11), number(22))) == "22");
  assert(reveal(ops.min(number(9), number(-2))) == "-2");
  assert(reveal(ops.max(number(9), number(-2))) == "9");

  std::filesystem::remove_all(directory);
  std::cout << "SecureOps OFF tests passed\n";
}
