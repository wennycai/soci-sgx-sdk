#include "protocol/threshold_wire.hpp"

#include <arpa/inet.h>
#include <future>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdexcept>
#include <sys/socket.h>
#include <unistd.h>

namespace {

void require(bool condition, const char* message) {
  if (!condition) throw std::runtime_error(message);
}

void requireNoDelay(int fd) {
  int enabled = 0;
  socklen_t size = sizeof(enabled);
  require(getsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &enabled, &size) == 0,
          "TCP_NODELAY getsockopt failed");
  require(enabled == 1, "TCP_NODELAY is not enabled");
}

}  // namespace

int main() {
  const int listener = socket(AF_INET, SOCK_STREAM, 0);
  require(listener >= 0, "listener socket failed");
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  address.sin_port = 0;
  require(bind(listener, reinterpret_cast<sockaddr*>(&address),
               sizeof(address)) == 0,
          "listener bind failed");
  require(listen(listener, 1) == 0, "listener listen failed");
  socklen_t address_size = sizeof(address);
  require(getsockname(listener, reinterpret_cast<sockaddr*>(&address),
                      &address_size) == 0,
          "listener getsockname failed");

  auto accepted = std::async(std::launch::async, [&] {
    const int fd = accept(listener, nullptr, nullptr);
    require(fd >= 0, "accept failed");
    soci::protocol::wire::setTcpNoDelay(fd);
    requireNoDelay(fd);
    const auto request = soci::protocol::wire::receiveFrame(fd);
    require(request.size() == 256 * 1024, "request frame size changed");
    for (std::size_t i = 0; i < request.size(); ++i)
      require(request[i] == static_cast<std::uint8_t>(i),
              "request frame payload changed");
    soci::protocol::wire::sendFrame(fd, {9, 8, 7});
    close(fd);
  });

  const int client = soci::protocol::wire::connectTcp(
      "127.0.0.1", ntohs(address.sin_port));
  requireNoDelay(client);
  soci::protocol::wire::Bytes payload(256 * 1024);
  for (std::size_t i = 0; i < payload.size(); ++i)
    payload[i] = static_cast<std::uint8_t>(i);
  soci::protocol::wire::sendFrame(client, payload);
  require(soci::protocol::wire::receiveFrame(client) ==
              soci::protocol::wire::Bytes({9, 8, 7}),
          "response frame payload changed");
  close(client);
  accepted.get();
  close(listener);
}
