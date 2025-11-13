#include "dns_utils.h"
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <iostream>
#include <cstring>

#include <arpa/inet.h>

std::string extractIPv4(const std::vector<uint8_t> &response)
{
    if (response.size() < 12)
        return "";

    const uint8_t *data = response.data();

    // DNS header fields
    uint16_t qdCount = ntohs(*(uint16_t *)(data + 4));
    uint16_t anCount = ntohs(*(uint16_t *)(data + 6));

    size_t offset = 12; // Skip header

    // Skip Question Section
    while (qdCount--)
    {
        // Skip domain name (QNAME)
        while (offset < response.size() && response[offset] != 0)
            offset += (response[offset] + 1);
        offset++; // null terminator

        offset += 4; // QTYPE + QCLASS
    }

    // Parse Answer Section
    while (anCount-- && offset < response.size())
    {
        // Skip NAME (may use compression)
        if (response[offset] & 0xC0)
        {
            offset += 2; // compressed pointer
        }
        else
        {
            while (response[offset] != 0)
                offset += (response[offset] + 1);
            offset++;
        }

        // TYPE + CLASS + TTL + RDLENGTH
        if (offset + 10 > response.size())
            return "";

        uint16_t type = ntohs(*(uint16_t *)&response[offset]);
        offset += 2;
        uint16_t classCode = ntohs(*(uint16_t *)&response[offset]);
        offset += 2;
        uint32_t ttl = ntohl(*(uint32_t *)&response[offset]);
        offset += 4;
        uint16_t rdLength = ntohs(*(uint16_t *)&response[offset]);
        offset += 2;

        // If this is an IPv4 A record
        if (type == 1 && classCode == 1 && rdLength == 4)
        {
            struct in_addr addr;
            memcpy(&addr, &response[offset], 4);
            return std::string(inet_ntoa(addr));
        }

        offset += rdLength; // Skip RDATA
    }

    return "";
}

std::vector<uint8_t> queryUpstream(const std::vector<uint8_t> &query,
                                   const std::string &dnsServerIP,
                                   int port)
{
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
        return {};

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, dnsServerIP.c_str(), &addr.sin_addr);

    sendto(sock, query.data(), query.size(), 0, (sockaddr *)&addr, sizeof(addr));

    std::vector<uint8_t> buffer(512);
    sockaddr_in from{};
    socklen_t fromlen = sizeof(from);
    ssize_t len = recvfrom(sock, buffer.data(), buffer.size(), 0,
                           (sockaddr *)&from, &fromlen);

    close(sock);
    if (len <= 0)
        return {};
    buffer.resize(len);
    return buffer;
}

uint32_t extractTTL(const std::vector<uint8_t> &response)
{
    if (response.size() < sizeof(DNSHeader))
        return 60;
    size_t offset = sizeof(DNSHeader);

    while (offset < response.size() && response[offset] != 0)
    {
        if (response[offset] >= 192)
        {
            offset += 2;
            break;
        }
        offset += response[offset] + 1;
    }
    offset += 1 + 4;

    if (offset + 10 > response.size())
        return 60;

    offset += 4;
    offset += 2;
    uint32_t ttl = ntohl(*(uint32_t *)&response[offset]);
    return (ttl > 0 && ttl < 86400) ? ttl : 60;
}

std::string extractDomainName(const std::vector<uint8_t> &query)
{
    std::string domain;
    size_t pos = sizeof(DNSHeader);
    while (pos < query.size() && query[pos] != 0)
    {
        int len = query[pos++];
        for (int i = 0; i < len && pos < query.size(); i++)
            domain.push_back(query[pos++]);
        domain.push_back('.');
    }
    return domain;
}
