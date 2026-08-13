#include "protocol/threshold_protocol.hpp"

#include <arpa/inet.h>
#include <cassert>
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

}  // namespace

int main(int argc, char** argv) {
  if (argc != 5) return 2;
  const auto mode = std::string(argv[4]) == "SIM"
                        ? soci::protocol::ThresholdMode::sim
                        : soci::protocol::ThresholdMode::hw;
  const auto directory = std::filesystem::temp_directory_path() /
                         ("soci-threshold-ops-" + std::to_string(getpid()));
  std::filesystem::create_directories(directory);
  pid_t server = -1;
  try {
    soci::protocol::provisionThresholdKeys(argv[1], directory.string(), 3072,
                                           mode);
    const int port = unusedPort();
    server = fork();
    if (server == 0) {
      try {
        const int result = soci::protocol::runThresholdCsp(
            argv[3], directory.string(), port, mode);
        _exit(result);
      } catch (...) {
        _exit(1);
      }
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(250));
    soci::protocol::ThresholdProtocolClient protocol(
        argv[2], directory.string(), "127.0.0.1", port, mode);
    const soci::secure::NumericDomain domain{1'000'000, 100, 32, 48, 64, 64};
    soci::protocol::ThresholdSecureOps ops(protocol, domain);
    bool rejected = false;
    try {
      soci::secure::Ciphertext raw{{1, 2, 3}};
      (void)ops.add(raw, ops.encryptConstant(1));
    } catch (const std::invalid_argument&) {
      rejected = true;
    }
    assert(rejected);
    const auto number = [&](std::int64_t value) {
      return ops.encryptConstant(value);
    };
    const auto reveal = [&](const soci::secure::Ciphertext& value) {
      assert(value.bytes.size() >= 12);
      assert(std::memcmp(value.bytes.data(), "SOCI", 4) == 0);
      assert(value.bytes[4] == 1 && value.bytes[5] == 1);
      mpz_class raw;
      mpz_import(raw.get_mpz_t(), value.bytes.size() - 12, 1, 1, 1, 0,
                 value.bytes.data() + 12);
      return protocol.decryptForTesting(raw).get_si();
    };
    const auto revealBit = [&](const soci::secure::EncryptedBit& value) {
      return reveal(value.ciphertext());
    };

    assert(reveal(ops.add(number(5), number(3))) == 8);
    assert(reveal(ops.scalarMul(number(5), -3)) == -15);
    assert(reveal(ops.secureMul(number(-5), number(3))) == -15);
    assert(revealBit(ops.greaterThan(number(5), number(3))) == 1);
    assert(revealBit(ops.greaterThan(number(3), number(5))) == 0);
    assert(revealBit(ops.greaterThan(number(5), number(5))) == 0);
    assert(revealBit(ops.lessThan(number(-5), number(3))) == 1);
    assert(revealBit(ops.equal(number(-5), number(-5))) == 1);
    const auto yes = ops.greaterThan(number(5), number(3));
    const auto no = ops.greaterThan(number(3), number(5));
    assert(revealBit(ops.bitNot(yes)) == 0);
    assert(revealBit(ops.bitAnd(yes, no)) == 0);
    assert(revealBit(ops.bitOr(yes, no)) == 1);
    assert(reveal(ops.select(yes, number(11), number(22))) == 11);
    assert(reveal(ops.min(number(9), number(-2))) == -2);
    assert(reveal(ops.max(number(9), number(-2))) == 9);
    assert(reveal(ops.secureMul(number((std::int64_t{1} << 31) - 1),
                                number(1))) ==
           (std::int64_t{1} << 31) - 1);

    rejected = false;
    try {
      soci::protocol::ThresholdSecureOps invalid(protocol, {});
    } catch (const std::invalid_argument&) {
      rejected = true;
    }
    assert(rejected);
    rejected = false;
    try {
      auto excessive = domain;
      excessive.max_linear_bits = 129;
      soci::protocol::ThresholdSecureOps invalid(protocol, excessive);
    } catch (const std::invalid_argument&) {
      rejected = true;
    }
    assert(rejected);

    protocol.requestServerShutdown();
    int status = 0;
    waitpid(server, &status, 0);
    server = -1;
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    std::filesystem::remove_all(directory);
    std::cout << "ThresholdSecureOps " << argv[4]
              << " integration tests passed\n";
    return 0;
  } catch (const std::exception& error) {
    if (server > 0) {
      kill(server, SIGTERM);
      waitpid(server, nullptr, 0);
    }
    std::filesystem::remove_all(directory);
    std::cerr << error.what() << '\n';
    return 1;
  }
}
