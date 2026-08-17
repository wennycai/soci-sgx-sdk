#include "protocol/threshold_wire.hpp"

#include <arpa/inet.h>
#include <chrono>
#include <cstring>
#include <fstream>
#include <netdb.h>
#include <netinet/tcp.h>
#include <stdexcept>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

namespace soci::protocol::wire {
namespace {
using Clock = std::chrono::steady_clock;

void transferExact(int fd, void* buffer, std::size_t size, bool write) {
  auto* cursor = static_cast<std::uint8_t*>(buffer);
  while (size != 0) {
    const auto count = write ? send(fd, cursor, size, MSG_NOSIGNAL)
                             : recv(fd, cursor, size, 0);
    if (count <= 0) throw std::runtime_error("socket closed");
    cursor += count;
    size -= static_cast<std::size_t>(count);
  }
}
}  // namespace

std::uint32_t readU32(const std::uint8_t* p) {
  return (std::uint32_t(p[0]) << 24) | (std::uint32_t(p[1]) << 16) |
         (std::uint32_t(p[2]) << 8) | p[3];
}

void writeU32(std::uint8_t* p, std::uint32_t value) {
  p[0] = value >> 24;
  p[1] = value >> 16;
  p[2] = value >> 8;
  p[3] = value;
}

std::uint64_t readU64(const std::uint8_t* p) {
  return (std::uint64_t(readU32(p)) << 32) | readU32(p + 4);
}

void appendU64(Bytes& output, std::uint64_t value) {
  const auto offset=output.size();output.resize(offset+8);
  writeU32(output.data()+offset,static_cast<std::uint32_t>(value>>32));
  writeU32(output.data()+offset+4,static_cast<std::uint32_t>(value));
}

void appendInteger(Bytes& output, const mpz_class& value) {
  const std::size_t size = (mpz_sizeinbase(value.get_mpz_t(), 2) + 7) / 8;
  if (size == 0 || size > UINT32_MAX || output.size() > SIZE_MAX - 4 - size)
    throw std::runtime_error("integer too large");
  const std::size_t offset = output.size();
  output.resize(offset + 4 + size);
  writeU32(output.data() + offset, static_cast<std::uint32_t>(size));
  std::size_t written = 0;
  mpz_export(output.data() + offset + 4, &written, 1, 1, 1, 0,
             value.get_mpz_t());
}

mpz_class takeInteger(const Bytes& input, std::size_t& offset) {
  if (offset + 4 > input.size()) throw std::runtime_error("short integer");
  const auto size = readU32(input.data() + offset);
  offset += 4;
  if (size == 0 || size > input.size() - offset)
    throw std::runtime_error("bad integer");
  mpz_class value;
  mpz_import(value.get_mpz_t(), size, 1, 1, 1, 0, input.data() + offset);
  offset += size;
  return value;
}

Bytes readFile(const std::string& path) {
  std::ifstream stream(path, std::ios::binary);
  if (!stream) throw std::runtime_error("cannot read " + path);
  return Bytes(std::istreambuf_iterator<char>(stream), {});
}

void writeFile(const std::string& path, const std::uint8_t* data,
               std::size_t size) {
  std::ofstream stream(path, std::ios::binary | std::ios::trunc);
  if (!stream || !stream.write(reinterpret_cast<const char*>(data), size))
    throw std::runtime_error("cannot write " + path);
}

void sendFrame(int fd, const Bytes& payload) {
  if (payload.size() > UINT32_MAX) throw std::runtime_error("frame too large");
  std::uint8_t header[4];
  writeU32(header, static_cast<std::uint32_t>(payload.size()));
  iovec vectors[2]{{header, sizeof(header)},
                    {const_cast<std::uint8_t*>(payload.data()),
                     payload.size()}};
  std::size_t index = 0;
  while (index < 2) {
    msghdr message{};
    message.msg_iov = vectors + index;
    message.msg_iovlen = 2 - index;
    const auto sent = sendmsg(fd, &message, MSG_NOSIGNAL);
    if (sent <= 0) throw std::runtime_error("socket closed");
    auto remaining = static_cast<std::size_t>(sent);
    while (index < 2 && remaining >= vectors[index].iov_len) {
      remaining -= vectors[index].iov_len;
      ++index;
    }
    if (index < 2 && remaining != 0) {
      vectors[index].iov_base =
          static_cast<std::uint8_t*>(vectors[index].iov_base) + remaining;
      vectors[index].iov_len -= remaining;
    }
  }
}

Bytes receiveFrame(int fd) {
  std::uint8_t header[4];
  transferExact(fd, header, sizeof(header), false);
  const auto size = readU32(header);
  if (size > 4 * 1024 * 1024) throw std::runtime_error("frame too large");
  Bytes payload(size);
  if (!payload.empty()) transferExact(fd, payload.data(), payload.size(), false);
  return payload;
}

void setTcpNoDelay(int fd) {
  const int enabled = 1;
  if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &enabled, sizeof(enabled)) != 0)
    throw std::runtime_error("cannot enable TCP_NODELAY");
}

int connectTcp(const std::string& host, int port) {
  const auto service = std::to_string(port);
  for (int attempt = 0; attempt < 60; ++attempt) {
    addrinfo hints{}, *addresses = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host.c_str(), service.c_str(), &hints, &addresses) == 0) {
      for (auto* address = addresses; address; address = address->ai_next) {
        const int fd = socket(address->ai_family, address->ai_socktype,
                              address->ai_protocol);
        if (fd >= 0 && connect(fd, address->ai_addr, address->ai_addrlen) == 0) {
          try {
            setTcpNoDelay(fd);
          } catch (...) {
            close(fd);
            freeaddrinfo(addresses);
            throw;
          }
          freeaddrinfo(addresses);
          return fd;
        }
        if (fd >= 0) close(fd);
      }
      freeaddrinfo(addresses);
    }
    usleep(250000);
  }
  throw std::runtime_error("connect CSP failed: " + host + ":" + service);
}

Bytes request(int fd, char operation, const std::vector<mpz_class>& values,
              double* network_microseconds) {
  Bytes payload{static_cast<std::uint8_t>(operation)};
  for (const auto& value : values) appendInteger(payload, value);
  return requestPayload(fd, std::move(payload), network_microseconds);
}

Bytes requestPayload(int fd, Bytes payload, double* network_microseconds) {
  const auto start = Clock::now();
  sendFrame(fd, payload);
  auto reply = receiveFrame(fd);
  if (network_microseconds) {
    *network_microseconds +=
        std::chrono::duration<double, std::micro>(Clock::now() - start).count();
  }
  if (reply.empty() || reply.front() != 0)
    throw std::runtime_error("CSP request failed");
  return Bytes(reply.begin() + 1, reply.end());
}

}  // namespace soci::protocol::wire
