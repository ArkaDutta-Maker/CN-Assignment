#include "dns_server.h"
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <iostream>

DNSServer::DNSServer(int p) : port(p) {}

std::vector<uint8_t> DNSServer::readTCPQuery(int clientSock)
{
    uint16_t length;
    if (recv(clientSock, &length, sizeof(length), MSG_WAITALL) <= 0)
        return {};
    length = ntohs(length);
    std::vector<uint8_t> buffer(length);
    recv(clientSock, buffer.data(), length, MSG_WAITALL);
    return buffer;
}

void DNSServer::sendTCPResponse(int clientSock, const std::vector<uint8_t> &resp)
{
    uint16_t len = htons(resp.size());
    send(clientSock, &len, sizeof(len), 0);
    send(clientSock, resp.data(), resp.size(), 0);
}

void DNSServer::handleClient(int clientSock)
{
    std::vector<uint8_t> query = readTCPQuery(clientSock);
    if (query.empty())
    {
        close(clientSock);
        return;
    }

    std::string domain = extractDomainName(query);
    std::vector<uint8_t> response;

    if (cache.get(domain, response))
    {
        std::cout << "[Cache Hit] " << domain << "\n";

        if (response.size() >= sizeof(DNSHeader) && query.size() >= sizeof(DNSHeader))
        {
            const DNSHeader *reqHeader = reinterpret_cast<const DNSHeader *>(query.data());
            DNSHeader *respHeader = reinterpret_cast<DNSHeader *>(response.data());
            respHeader->id = reqHeader->id;
            std::cout << "   ↳ Updated DNS ID to match query\n";
        }
    }
    else
    {
        std::cout << "[Cache Miss] Forwarding -> " << domain << "\n";
        response = queryUpstream(query, "8.8.8.8", 53);

        if (!response.empty())
        {
            uint32_t ttl = extractTTL(response);
            std::cout << "TTL = " << ttl << " sec\n";
            cache.store(domain, response, ttl);
        }
        else
        {
            std::cerr << "Upstream query failed for " << domain << "\n";
            close(clientSock);
            return;
        }
    }

    sendTCPResponse(clientSock, response);
    close(clientSock);
}

void DNSServer::start()
{
    int serverSock = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSock < 0)
    {
        perror("socket");
        return;
    }

    int opt = 1;
    setsockopt(serverSock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(serverSock, (sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("bind");
        close(serverSock);
        return;
    }

    listen(serverSock, 10);
    std::cout << "[DNS Server] Listening on port " << port << " (TCP)\n";

    while (true)
    {
        sockaddr_in clientAddr{};
        socklen_t len = sizeof(clientAddr);
        int clientSock = accept(serverSock, (sockaddr *)&clientAddr, &len);
        if (clientSock < 0)
            continue;
        std::thread(&DNSServer::handleClient, this, clientSock).detach();
    }
}
