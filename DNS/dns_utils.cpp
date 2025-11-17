#include "dns_utils.h"
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <iostream>
#include <cstring>

#include <arpa/inet.h>
#include <vector>
#include <string>
#include <cstring>
#include <cstdlib>

std::vector<std::string> extractAuthorityServers(const std::vector<uint8_t> &response)
{
    std::vector<std::string> nsList;
    if (response.size() < 12)
        return nsList;
    const uint8_t *data = response.data();
    uint16_t qdCount = ntohs(*(uint16_t *)(data + 4));
    uint16_t anCount = ntohs(*(uint16_t *)(data + 6));
    uint16_t nsCount = ntohs(*(uint16_t *)(data + 8));
    size_t offset = 12;
    while (qdCount--)
    {
        while (offset < response.size() && response[offset] != 0)
            offset += response[offset] + 1;
        offset++;    // null
        offset += 4; // QTYPE + QCLASS
    }
    for (int i = 0; i < anCount; i++)
    {
        if (offset + 10 > response.size())
            return nsList;
        if (response[offset] & 0xC0)
            offset += 2;
        else
        {
            while (response[offset] != 0)
                offset += response[offset] + 1;
            offset++;
        }
        offset += 2 + 2 + 4;
        uint16_t rdlen = ntohs(*(uint16_t *)(response.data() + offset));
        offset += 2 + rdlen;
    }
    // Parse Authority section
    for (int i = 0; i < nsCount; i++)
    {
        if (offset + 10 > response.size())
            return nsList;
        if (response[offset] & 0xC0)
            offset += 2;
        else
        {
            while (response[offset] != 0)
                offset += response[offset] + 1;
            offset++;
        }
        uint16_t type = ntohs(*(uint16_t *)(response.data() + offset));
        offset += 2;
        offset += 2 + 4; // CLASS + TTL
        uint16_t rdlen = ntohs(*(uint16_t *)(response.data() + offset));
        offset += 2;
        if (type == 2 && rdlen > 0)
        { // NS record
            size_t nsOffset = offset;
            std::string nsDomain;
            while (nsOffset < response.size() && response[nsOffset] != 0)
            {
                int len = response[nsOffset++];
                for (int j = 0; j < len && nsOffset < response.size(); j++)
                    nsDomain.push_back(response[nsOffset++]);
                nsDomain.push_back('.');
            }
            nsList.push_back(nsDomain);
        }
        offset += rdlen;
    }
    return nsList;
}

std::map<std::string, std::string> extractAdditionalIPs(const std::vector<uint8_t> &response)
{
    std::map<std::string, std::string> ipMap;
    if (response.size() < 12)
        return ipMap;
    const uint8_t *data = response.data();
    uint16_t qdCount = ntohs(*(uint16_t *)(data + 4));
    uint16_t anCount = ntohs(*(uint16_t *)(data + 6));
    uint16_t nsCount = ntohs(*(uint16_t *)(data + 8));
    uint16_t arCount = ntohs(*(uint16_t *)(data + 10));
    size_t offset = 12;
    while (qdCount--)
    {
        while (offset < response.size() && response[offset] != 0)
            offset += response[offset] + 1;
        offset++;
        offset += 4;
    }
    int skipCount = anCount + nsCount;
    for (int i = 0; i < skipCount; i++)
    {
        if (offset + 10 > response.size())
            return ipMap;
        if (response[offset] & 0xC0)
            offset += 2;
        else
        {
            while (response[offset] != 0)
                offset += response[offset] + 1;
            offset++;
        }
        offset += 2 + 2 + 4;
        uint16_t rdlen = ntohs(*(uint16_t *)(response.data() + offset));
        offset += 2 + rdlen;
    }
    // Additional section
    for (int i = 0; i < arCount; i++)
    {
        if (offset + 10 > response.size())
            break;
        size_t nameOffset = offset;
        std::string name;
        if (response[offset] & 0xC0)
        {
            uint16_t ptr = ntohs(*(uint16_t *)(response.data() + offset)) & 0x3FFF;
            offset += 2;
            size_t tmp = ptr;
            while (tmp < response.size() && response[tmp] != 0)
            {
                int len = response[tmp++];
                for (int j = 0; j < len && tmp < response.size(); j++)
                    name.push_back(response[tmp++]);
                name.push_back('.');
            }
        }
        else
        {
            while (offset < response.size() && response[offset] != 0)
            {
                int len = response[offset++];
                for (int j = 0; j < len && offset < response.size(); j++)
                    name.push_back(response[offset++]);
                name.push_back('.');
            }
            offset++;
        }
        uint16_t type = ntohs(*(uint16_t *)(response.data() + offset));
        offset += 2;
        offset += 2 + 4; // CLASS + TTL
        uint16_t rdlen = ntohs(*(uint16_t *)(response.data() + offset));
        offset += 2;
        if (type == 1 && rdlen == 4)
        { // A record
            struct in_addr addr;
            memcpy(&addr, &response[offset], 4);
            ipMap[name] = std::string(inet_ntoa(addr));
        }
        offset += rdlen;
    }
    return ipMap;
}

std::vector<uint8_t> buildQuery(const std::string &domain)
{
    std::vector<uint8_t> query(sizeof(DNSHeader), 0);
    DNSHeader *hdr = reinterpret_cast<DNSHeader *>(query.data());
    hdr->id = htons(rand() % 65536);
    hdr->flags = htons(0x0100); // standard query
    hdr->qdcount = htons(1);
    // Encode domain name
    size_t pos = query.size();
    std::string copy = domain;
    size_t start = 0;
    while (start < copy.size())
    {
        size_t dot = copy.find('.', start);
        if (dot == std::string::npos)
            dot = copy.size();
        size_t len = dot - start;
        query.push_back(len);
        for (size_t i = 0; i < len; ++i)
            query.push_back(copy[start + i]);
        start = dot + 1;
    }
    query.push_back(0); // null terminator
    // QTYPE=A, QCLASS=IN
    query.push_back(0);
    query.push_back(1);
    query.push_back(0);
    query.push_back(1);
    return query;
}

static std::vector<uint8_t> sendQuery(const std::vector<uint8_t> &query, const std::string &server, int port)
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
    // If truncated, try TCP
    const DNSHeader *hdr = reinterpret_cast<const DNSHeader *>(buffer);
    if (ntohs(hdr->flags) & 0x0200)
    {
        int tcpSock = socket(AF_INET, SOCK_STREAM, 0);
        if (tcpSock < 0)
            return {};
        if (connect(tcpSock, (sockaddr *)&addr, sizeof(addr)) < 0)
        {
            close(tcpSock);
            return {};
        }
        uint16_t len = htons(query.size());
        send(tcpSock, &len, sizeof(len), 0);
        send(tcpSock, query.data(), query.size(), 0);
        uint16_t respLen;
        if (recv(tcpSock, &respLen, sizeof(respLen), MSG_WAITALL) <= 0)
        {
            close(tcpSock);
            return {};
        }
        respLen = ntohs(respLen);
        std::vector<uint8_t> tcpResp(respLen);
        if (recv(tcpSock, tcpResp.data(), respLen, MSG_WAITALL) <= 0)
        {
            close(tcpSock);
            return {};
        }
        close(tcpSock);
        return tcpResp;
    }
    return std::vector<uint8_t>(buffer, buffer + recvLen);
}

static const char *rootServers[] = {
    "198.41.0.4",     // a.root-servers.net
    "199.9.14.201",   // b.root-servers.net
    "192.33.4.12",    // c.root-servers.net
    "199.7.91.13",    // d.root-servers.net
    "192.203.230.10", // e.root-servers.net
    "192.5.5.241",    // f.root-servers.net
    "192.112.36.4",   // g.root-servers.net
    "198.97.190.53",  // h.root-servers.net
    "192.36.148.17",  // i.root-servers.net
    "192.58.128.30",  // j.root-servers.net
    "193.0.14.129",   // k.root-servers.net
    "199.7.83.42",    // l.root-servers.net
    "202.12.27.33"    // m.root-servers.net
};

// Recursively resolve a DNS query starting from root servers
std::vector<uint8_t> recursiveResolve(const std::vector<uint8_t> &query, int port)
{
    // Extract domain from query
    std::string domain = extractDomainName(query);
    std::vector<std::string> nextServers;
    for (const char *ip : rootServers)
        nextServers.push_back(ip);
    int maxDepth = 20;
    for (int depth = 0; depth < maxDepth; ++depth)
    {
        for (const std::string &server : nextServers)
        {
            auto response = sendQuery(query, server, port);
            if (response.empty())
                continue;
            // If answer section present, return
            const DNSHeader *hdr = reinterpret_cast<const DNSHeader *>(response.data());
            if (ntohs(hdr->ancount) > 0)
                return response;
            // If NXDOMAIN or error, return
            if ((ntohs(hdr->flags) & 0x000F) != 0)
                return response;
            // Otherwise, follow referrals
            auto nsList = extractAuthorityServers(response);
            auto ipMap = extractAdditionalIPs(response);
            std::vector<std::string> newServers;
            for (const std::string &ns : nsList)
            {
                std::string nsTrim = ns;
                if (!nsTrim.empty() && nsTrim.back() == '.')
                    nsTrim.pop_back();
                if (ipMap.count(nsTrim + "."))
                    newServers.push_back(ipMap[nsTrim + "."]);
                else if (ipMap.count(nsTrim))
                    newServers.push_back(ipMap[nsTrim]);
            }
            // If no glue records, try to resolve NS IPs recursively
            if (newServers.empty() && !nsList.empty())
            {
                for (const std::string &ns : nsList)
                {
                    std::string nsTrim = ns;
                    if (!nsTrim.empty() && nsTrim.back() == '.')
                        nsTrim.pop_back();
                    auto nsQuery = buildQuery(nsTrim);
                    auto nsResp = recursiveResolve(nsQuery, port);
                    std::string nsIP = extractIPv4(nsResp);
                    if (!nsIP.empty())
                        newServers.push_back(nsIP);
                }
            }
            if (!newServers.empty())
            {
                nextServers = newServers;
                break;
            }
        }
    }
    return {};
}

std::string extractIPv4(const std::vector<uint8_t> &response)
{
    if (response.size() < 12)
        return "";

    const uint8_t *data = response.data();

    uint16_t qdCount = ntohs(*(uint16_t *)(data + 4));
    uint16_t anCount = ntohs(*(uint16_t *)(data + 6));

    size_t offset = 12; // Skip header

    while (qdCount--)
    {
        while (offset < response.size() && response[offset] != 0)
            offset += (response[offset] + 1);
        offset++; // null terminator

        offset += 4;
    }

    while (anCount-- && offset < response.size())
    {
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

std::string extractRecordType(const std::vector<uint8_t> &response)
{
    if (response.size() < sizeof(DNSHeader))
        return "";

    const DNSHeader *hdr = reinterpret_cast<const DNSHeader *>(response.data());
    uint16_t qdCount = ntohs(hdr->qdcount);
    uint16_t anCount = ntohs(hdr->ancount);

    if (anCount == 0)
        return "";

    size_t offset = sizeof(DNSHeader);

    for (int i = 0; i < qdCount; ++i)
    {
        while (offset < response.size() && response[offset] != 0)
            offset += response[offset] + 1;
        offset += 1;

        if (offset + 4 > response.size())
            return "";
        offset += 4;
    }

    if (offset + 10 > response.size())
        return "";

    if ((response[offset] & 0xC0) == 0xC0)
    {
        offset += 2; // pointer
    }
    else
    {
        while (offset < response.size() && response[offset] != 0)
            offset += response[offset] + 1;
        offset += 1;
    }

    if (offset + 10 > response.size())
        return "";

    uint16_t type = ntohs(*reinterpret_cast<const uint16_t *>(&response[offset]));
    offset += 2; // TYPE
    offset += 2; // CLASS
    offset += 4; // TTL
    uint16_t rdlength = ntohs(*reinterpret_cast<const uint16_t *>(&response[offset]));
    offset += 2;        // RDLENGTH
    offset += rdlength; // skip RDATA

    // Map type to string
    static std::unordered_map<uint16_t, std::string> typeMap = {
        {1, "A"}, {2, "NS"}, {5, "CNAME"}, {6, "SOA"}, {12, "PTR"}, {15, "MX"}, {16, "TXT"}, {28, "AAAA"}, {33, "SRV"}, {257, "CAA"}};

    return typeMap.count(type) ? typeMap[type] : "UNKNOWN";
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
std::vector<std::string> extractResolutionChain(const std::vector<uint8_t> &response)
{
    std::vector<std::string> chain;

    if (response.empty())
        return chain;

    size_t offset = sizeof(DNSHeader);

    const DNSHeader *hdr = reinterpret_cast<const DNSHeader *>(response.data());
    uint16_t qdCount = ntohs(hdr->qdcount);
    uint16_t anCount = ntohs(hdr->ancount);

    // Skip question section
    for (int i = 0; i < qdCount; ++i)
    {
        while (offset < response.size() && response[offset] != 0)
            offset += response[offset] + 1;
        offset += 1; // null terminator
        offset += 4; // QTYPE + QCLASS
    }

    // Parse all answers
    for (int i = 0; i < anCount; ++i)
    {
        if (offset + 10 > response.size())
            break;

        // Skip NAME
        if ((response[offset] & 0xC0) == 0xC0)
        {
            offset += 2; // pointer
        }
        else
        {
            while (offset < response.size() && response[offset] != 0)
                offset += response[offset] + 1;
            offset += 1;
        }

        if (offset + 10 > response.size())
            break;

        uint16_t type = ntohs(*reinterpret_cast<const uint16_t *>(&response[offset]));
        offset += 2; // TYPE
        offset += 2; // CLASS
        offset += 4; // TTL
        uint16_t rdlength = ntohs(*reinterpret_cast<const uint16_t *>(&response[offset]));
        offset += 2;

        if (offset + rdlength > response.size())
            break;

        if (type == 1) // A record
        {
            uint8_t a = response[offset];
            uint8_t b = response[offset + 1];
            uint8_t c = response[offset + 2];
            uint8_t d = response[offset + 3];
            chain.push_back(std::to_string(a) + "." + std::to_string(b) + "." +
                            std::to_string(c) + "." + std::to_string(d) + " (A)");
        }
        else if (type == 5) // CNAME
        {
            std::string cname;
            size_t cnameOffset = offset;
            while (cnameOffset < offset + rdlength)
            {
                uint8_t len = response[cnameOffset++];
                if (len == 0)
                    break;
                if ((len & 0xC0) == 0xC0)
                {
                    // pointer: get offset
                    uint16_t ptr = ((len & 0x3F) << 8) | response[cnameOffset++];
                    size_t savedOffset = cnameOffset;
                    cnameOffset = ptr; // jump
                    // recursively decode labels
                    while (response[cnameOffset] != 0)
                    {
                        uint8_t l = response[cnameOffset++];
                        if ((l & 0xC0) == 0xC0)
                        {
                            uint16_t p = ((l & 0x3F) << 8) | response[cnameOffset++];
                            cnameOffset = p;
                        }
                        else
                        {
                            for (int j = 0; j < l; ++j)
                                cname += response[cnameOffset++];
                            cname += '.';
                        }
                    }
                    cnameOffset = savedOffset;
                    break;
                }
                else
                {
                    for (int j = 0; j < len; ++j)
                        cname += response[cnameOffset++];
                    cname += '.';
                }
            }
            if (!cname.empty() && cname.back() == '.')
                cname.pop_back();
            chain.push_back(cname + " (CNAME)");
        }

        offset += rdlength;
    }

    return chain;
}