#pragma once
/// Minimal TCP client for Cheat Engine ceserver-compatible endpoints.

#include <cstdint>
#include <cstddef>
#include <expected>
#include <string>

namespace ce::os {

struct CEServerVersionInfo {
    int32_t protocolVersion = 0;
    std::string versionString;
};

class CEServerClient {
public:
    CEServerClient() = default;
    ~CEServerClient();

    CEServerClient(const CEServerClient&) = delete;
    CEServerClient& operator=(const CEServerClient&) = delete;

    bool connectTcp(const std::string& host, uint16_t port, std::string& error);
    void close();
    bool isConnected() const { return fd_ >= 0; }

    std::expected<CEServerVersionInfo, std::string> getVersion();

private:
    bool sendAll(const void* data, size_t size, std::string& error);
    bool recvAll(void* data, size_t size, std::string& error);

    int fd_ = -1;
};

} // namespace ce::os
