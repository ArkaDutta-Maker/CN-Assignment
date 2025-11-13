#include "dns_server.h"
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <iostream>
#include <thread>

DNSServer::DNSServer(int p) : port(p) {}

DNSCache *DNSServer::getCache()
{
    return &(this->cache);
}

std::vector<uint8_t> DNSServer::readTCPQuery(int clientSock)
{
    uint16_t length;
    if (recv(clientSock, &length, sizeof(length), MSG_WAITALL) <= 0)
        return {};

    length = ntohs(length);
    std::vector<uint8_t> buffer(length);

    if (recv(clientSock, buffer.data(), length, MSG_WAITALL) <= 0)
        return {};

    return buffer;
}

void DNSServer::sendTCPResponse(int clientSock, const std::vector<uint8_t> &response)
{
    uint16_t len = htons(response.size());
    send(clientSock, &len, sizeof(len), 0);
    send(clientSock, response.data(), response.size(), 0);
}

std::vector<uint8_t> DNSServer::queryUpstreamUDP(const std::vector<uint8_t> &query,
                                                 const std::string &server, int port)
{
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
        return {};

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, server.c_str(), &addr.sin_addr);

    sendto(sock, query.data(), query.size(), 0, (sockaddr *)&addr, sizeof(addr));

    uint8_t buffer[512];
    socklen_t addrLen = sizeof(addr);
    ssize_t recvLen = recvfrom(sock, buffer, sizeof(buffer), 0, (sockaddr *)&addr, &addrLen);

    close(sock);
    if (recvLen <= 0)
        return {};

    return std::vector<uint8_t>(buffer, buffer + recvLen);
}

std::vector<uint8_t> DNSServer::queryUpstreamTCP(const std::vector<uint8_t> &query,
                                                 const std::string &server, int port)
{
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
        return {};

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, server.c_str(), &addr.sin_addr);

    if (connect(sock, (sockaddr *)&addr, sizeof(addr)) < 0)
    {
        close(sock);
        return {};
    }

    uint16_t len = htons(query.size());
    send(sock, &len, sizeof(len), 0);
    send(sock, query.data(), query.size(), 0);

    uint16_t respLen;
    if (recv(sock, &respLen, sizeof(respLen), MSG_WAITALL) <= 0)
    {
        close(sock);
        return {};
    }

    respLen = ntohs(respLen);
    std::vector<uint8_t> response(respLen);

    if (recv(sock, response.data(), respLen, MSG_WAITALL) <= 0)
    {
        close(sock);
        return {};
    }

    close(sock);
    return response;
}

std::vector<uint8_t> DNSServer::queryUpstream(const std::vector<uint8_t> &query,
                                              const std::string &server, int port)
{
    auto response = queryUpstreamUDP(query, server, port);

    if (response.size() > 512)
    {
        std::cout << "↻ Upstream response >512 bytes — retrying via TCP\n";
        return queryUpstreamTCP(query, server, port);
    }

    if (!response.empty())
    {
        const DNSHeader *hdr = reinterpret_cast<const DNSHeader *>(response.data());
        if (ntohs(hdr->flags) & 0x0200)
        {
            std::cout << "↻ Truncated UDP response — retrying via TCP\n";
            return queryUpstreamTCP(query, server, port);
        }
    }

    return response;
}

void DNSServer::handleClient(int clientSock)
{
    auto query = readTCPQuery(clientSock);
    if (query.empty())
    {
        close(clientSock);
        return;
    }

    std::string domain = extractDomainName(query);
    std::vector<uint8_t> response;

    if (cache.get(domain, response))
    {
        std::cout << "[Cache Hit] (TCP) " << domain << "\n";
        if (response.size() >= sizeof(DNSHeader) && query.size() >= sizeof(DNSHeader))
        {
            auto reqHeader = reinterpret_cast<const DNSHeader *>(query.data());
            auto respHeader = reinterpret_cast<DNSHeader *>(response.data());

            std::cout << "\n";
            respHeader->id = reqHeader->id;
        }
    }
    else
    {
        std::cout << "[Cache Miss] (TCP) " << domain
                  << " | Query Size: " << query.size() << " bytes\n";

        response = queryUpstream(query, "8.8.8.8", 53);

        if (!response.empty())
        {
            uint32_t ttl = extractTTL(response);
            cache.store(domain, response, ttl);
        }
    }

    sendTCPResponse(clientSock, response);
    close(clientSock);
}

void DNSServer::handleUDP(int udpSock)
{
    sockaddr_in clientAddr{};
    socklen_t addrLen = sizeof(clientAddr);
    uint8_t buffer[512];

    ssize_t recvLen = recvfrom(udpSock, buffer, sizeof(buffer), 0,
                               (sockaddr *)&clientAddr, &addrLen);
    if (recvLen <= 0)
        return;

    std::vector<uint8_t> query(buffer, buffer + recvLen);
    std::string domain = extractDomainName(query);
    std::vector<uint8_t> response;

    if (cache.get(domain, response))
    {
        std::cout << "[Cache Hit] (UDP) " << domain << "\n";
        auto reqHeader = reinterpret_cast<const DNSHeader *>(query.data());
        auto respHeader = reinterpret_cast<DNSHeader *>(response.data());
        // for (auto i : response)
        // {
        //     std::cout << i << " ";
        // }
        respHeader->id = reqHeader->id;
    }
    else
    {
        std::cout << "[Cache Miss] (UDP) " << domain
                  << " | Query Size: " << query.size() << " bytes\n";

        response = queryUpstream(query, "8.8.8.8", 53);

        if (!response.empty())
        {
            uint32_t ttl = extractTTL(response);
            cache.store(domain, response, ttl);
        }
    }
    std::string ip = extractIPv4(response);
    if (!ip.empty())
    {
        std::cout << "[Resolved] " << domain << " -> " << ip << "\n";
    }
    sendto(udpSock, response.data(), response.size(), 0,
           (sockaddr *)&clientAddr, addrLen);
}

// =========================================================
//                   UDP Listener
// =========================================================

void DNSServer::udpListener()
{
    int udpSock = socket(AF_INET, SOCK_DGRAM, 0);
    if (udpSock < 0)
    {
        perror("UDP socket");
        return;
    }

    int opt = 1;
    setsockopt(udpSock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(udpSock, (sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("UDP bind");
        close(udpSock);
        return;
    }

    std::cout << "[DNS Server] Listening on port " << port << " (UDP)\n";

    while (true)
        handleUDP(udpSock);
}

// =========================================================
//                   Server Startup
// =========================================================

void DNSServer::start()
{
    std::thread(&DNSServer::udpListener, this).detach();

    int tcpSock = socket(AF_INET, SOCK_STREAM, 0);
    if (tcpSock < 0)
    {
        perror("TCP socket");
        return;
    }

    int opt = 1;
    setsockopt(tcpSock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(tcpSock, (sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("TCP bind");
        close(tcpSock);
        return;
    }

    listen(tcpSock, 10);
    std::cout << "[DNS Server] Listening on port " << port << " (TCP)\n";

    while (true)
    {
        sockaddr_in clientAddr{};
        socklen_t len = sizeof(clientAddr);
        int clientSock = accept(tcpSock, (sockaddr *)&clientAddr, &len);
        if (clientSock < 0)
            continue;

        std::thread(&DNSServer::handleClient, this, clientSock).detach();
    }
}
