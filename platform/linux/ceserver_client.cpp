#include "platform/linux/ceserver_client.hpp"

#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <vector>

namespace ce::os {
namespace {

constexpr uint8_t CMD_GETVERSION = 0;

std::string errnoString(const char* prefix) {
    return std::string(prefix) + ": " + std::strerror(errno);
}

} // namespace

CEServerClient::~CEServerClient() {
    close();
}

bool CEServerClient::connectTcp(const std::string& host, uint16_t port, std::string& error) {
    close();

    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    auto portText = std::to_string(port);
    addrinfo* results = nullptr;
    int gai = getaddrinfo(host.c_str(), portText.c_str(), &hints, &results);
    if (gai != 0) {
        error = gai_strerror(gai);
        return false;
    }

    for (auto* addr = results; addr; addr = addr->ai_next) {
        int candidate = ::socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
        if (candidate < 0)
            continue;

        if (::connect(candidate, addr->ai_addr, addr->ai_addrlen) == 0) {
            fd_ = candidate;
            freeaddrinfo(results);
            return true;
        }

        ::close(candidate);
    }

    error = errnoString("connect");
    freeaddrinfo(results);
    return false;
}

void CEServerClient::close() {
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
}

bool CEServerClient::sendAll(const void* data, size_t size, std::string& error) {
    auto* bytes = static_cast<const uint8_t*>(data);
    size_t sent = 0;
    while (sent < size) {
        ssize_t n = ::send(fd_, bytes + sent, size - sent, 0);
        if (n <= 0) {
            error = errnoString("send");
            return false;
        }
        sent += static_cast<size_t>(n);
    }
    return true;
}

bool CEServerClient::recvAll(void* data, size_t size, std::string& error) {
    auto* bytes = static_cast<uint8_t*>(data);
    size_t received = 0;
    while (received < size) {
        ssize_t n = ::recv(fd_, bytes + received, size - received, MSG_WAITALL);
        if (n <= 0) {
            error = errnoString("recv");
            return false;
        }
        received += static_cast<size_t>(n);
    }
    return true;
}

std::expected<CEServerVersionInfo, std::string> CEServerClient::getVersion() {
    if (fd_ < 0)
        return std::unexpected("not connected");

    std::string error;
    uint8_t command = CMD_GETVERSION;
    if (!sendAll(&command, sizeof(command), error))
        return std::unexpected(error);

    int32_t protocolVersion = 0;
    uint8_t stringSize = 0;
    if (!recvAll(&protocolVersion, sizeof(protocolVersion), error) ||
        !recvAll(&stringSize, sizeof(stringSize), error)) {
        return std::unexpected(error);
    }

    std::string versionString(stringSize, '\0');
    if (stringSize > 0 && !recvAll(versionString.data(), stringSize, error))
        return std::unexpected(error);

    return CEServerVersionInfo{protocolVersion, versionString};
}

} // namespace ce::os
