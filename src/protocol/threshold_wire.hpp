#pragma once

#include <gmpxx.h>

#include <cstdint>
#include <string>
#include <vector>

namespace soci::protocol::wire {

using Bytes = std::vector<std::uint8_t>;

std::uint32_t readU32(const std::uint8_t* data);
void writeU32(std::uint8_t* data, std::uint32_t value);
void appendInteger(Bytes& output, const mpz_class& value);
mpz_class takeInteger(const Bytes& input, std::size_t& offset);

Bytes readFile(const std::string& path);
void writeFile(const std::string& path, const std::uint8_t* data,
               std::size_t size);

void sendFrame(int fd, const Bytes& payload);
Bytes receiveFrame(int fd);
int connectTcp(const std::string& host, int port);
Bytes request(int fd, char operation, const std::vector<mpz_class>& values,
              double* network_microseconds = nullptr);

}  // namespace soci::protocol::wire
