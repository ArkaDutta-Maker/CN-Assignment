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
#include <set>

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

std::vector<uint8_t> buildQuery(const std::string &domain, uint16_t qtype)
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
    // QTYPE (A=1, AAAA=28), QCLASS=IN
    query.push_back((qtype >> 8) & 0xFF);
    query.push_back(qtype & 0xFF);
    query.push_back(0);
    query.push_back(1);
    return query;
}

std::vector<uint8_t> buildQuery(const std::string &domain)
{
    return buildQuery(domain, 1); // Default to A record
}

static std::vector<uint8_t> sendQuery(const std::vector<uint8_t> &query, const std::string &server, int port)
{
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
        return {};

    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

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
    "170.247.170.2",  // b.root-servers.net
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
    std::string domain = extractDomainName(query);
    uint16_t queryType = extractQueryType(query); // Extract A or AAAA from original query
    std::vector<std::string> nextServers;
    for (const char *ip : rootServers)
        nextServers.push_back(ip);
    int maxDepth = 20;
    std::string currentDomain = domain;
    std::vector<uint8_t> lastResponse;
    std::set<std::string> seenCNAMEs;
    std::vector<std::pair<std::string, std::string>> cnameChain; // Store (source, target) pairs

    for (int depth = 0; depth < maxDepth; ++depth)
    {
        bool found = false;
        for (const std::string &server : nextServers)
        {
            std::vector<uint8_t> q = buildQuery(currentDomain, queryType);
            std::vector<uint8_t> response = sendQuery(q, server, port);
            if (response.empty())
                continue;
            lastResponse = response;
            // Parse answer section for CNAME or A records for the currentDomain
            const DNSHeader *hdr = reinterpret_cast<const DNSHeader *>(response.data());
            uint16_t qdCount = ntohs(hdr->qdcount);
            uint16_t anCount = ntohs(hdr->ancount);
            size_t offset = sizeof(DNSHeader);
            // Skip question section
            for (int i = 0; i < qdCount; ++i)
            {
                while (offset < response.size() && response[offset] != 0)
                    offset++;
                offset++;    // null
                offset += 4; // QTYPE + QCLASS
            }
            std::string nextCNAME;
            std::vector<std::string> foundIPs;
            size_t answerStartOffset = offset;

            for (int i = 0; i < anCount; ++i)
            {
                size_t rrStart = offset;
                // Skip name (could be pointer or label)
                if (offset + 10 > response.size())
                    break;
                // Skip the name field
                if ((response[offset] & 0xC0) == 0xC0)
                {
                    offset += 2;
                }
                else
                {
                    while (offset < response.size() && response[offset] != 0)
                        offset += response[offset] + 1;
                    offset++;
                }
                if (offset + 10 > response.size())
                    break;
                uint16_t type = ntohs(*reinterpret_cast<const uint16_t *>(&response[offset]));
                offset += 2; // TYPE
                offset += 2; // CLASS
                offset += 4; // TTL
                uint16_t rdlength = ntohs(*reinterpret_cast<const uint16_t *>(&response[offset]));
                offset += 2;

                if (type == 5) // CNAME
                {
                    // Parse CNAME target
                    size_t cnameOffset = offset;
                    std::string cname;
                    while (cnameOffset < response.size() && response[cnameOffset] != 0)
                    {
                        if ((response[cnameOffset] & 0xC0) == 0xC0)
                        {
                            // pointer
                            uint16_t ptr = ntohs(*reinterpret_cast<const uint16_t *>(&response[cnameOffset])) & 0x3FFF;
                            size_t ptrOffset = ptr;
                            while (ptrOffset < response.size() && response[ptrOffset] != 0)
                            {
                                uint8_t len = response[ptrOffset++];
                                if (len == 0)
                                    break;
                                if (!cname.empty())
                                    cname += ".";
                                for (int k = 0; k < len && ptrOffset < response.size(); ++k)
                                    cname += (char)response[ptrOffset++];
                            }
                            break;
                        }
                        else
                        {
                            uint8_t len = response[cnameOffset++];
                            if (len == 0)
                                break;
                            if (!cname.empty())
                                cname += ".";
                            for (int k = 0; k < len && cnameOffset < response.size(); ++k)
                                cname += (char)response[cnameOffset++];
                        }
                    }
                    if (!cname.empty() && seenCNAMEs.find(cname) == seenCNAMEs.end())
                    {
                        nextCNAME = cname;
                        seenCNAMEs.insert(cname);
                        // Store CNAME mapping: currentDomain -> cname target
                        cnameChain.push_back({currentDomain, cname});
                    }
                }
                else if (type == 1 && rdlength == 4) // A
                {
                    char ipbuf[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &response[offset], ipbuf, sizeof(ipbuf));
                    foundIPs.push_back(std::string(ipbuf));
                }
                else if (type == 28 && rdlength == 16) // AAAA (IPv6)
                {
                    char ipbuf[INET6_ADDRSTRLEN];
                    inet_ntop(AF_INET6, &response[offset], ipbuf, sizeof(ipbuf));
                    foundIPs.push_back(std::string(ipbuf));
                }
                offset += rdlength;
            }
            if (!foundIPs.empty())
            {
                std::vector<uint8_t> finalResponse;

                finalResponse.insert(finalResponse.end(), query.begin(), query.begin() + sizeof(DNSHeader));

                DNSHeader *finalHdr = reinterpret_cast<DNSHeader *>(finalResponse.data());
                finalHdr->flags = htons(0x8180);
                finalHdr->nscount = htons(0);
                finalHdr->arcount = htons(0);

                // Count A records in the final response
                size_t aRecordCount = 0;
                size_t tmpOffset = answerStartOffset;
                for (int j = 0; j < anCount && tmpOffset < response.size(); ++j)
                {
                    if ((response[tmpOffset] & 0xC0) == 0xC0)
                        tmpOffset += 2;
                    else
                    {
                        while (tmpOffset < response.size() && response[tmpOffset] != 0)
                            tmpOffset += response[tmpOffset] + 1;
                        tmpOffset++;
                    }
                    if (tmpOffset + 10 > response.size())
                        break;
                    uint16_t recType = ntohs(*reinterpret_cast<const uint16_t *>(&response[tmpOffset]));
                    tmpOffset += 2 + 2 + 4; // TYPE + CLASS + TTL
                    uint16_t recRdlen = ntohs(*reinterpret_cast<const uint16_t *>(&response[tmpOffset]));
                    tmpOffset += 2 + recRdlen;
                    if (recType == 1 || recType == 28) // A or AAAA record
                        aRecordCount++;
                }

                finalHdr->ancount = htons(cnameChain.size() + aRecordCount);

                // Copy question section from original query
                size_t qOffset = sizeof(DNSHeader);
                while (qOffset < query.size() && query[qOffset] != 0)
                    qOffset++;
                qOffset += 1 + 4; // null + QTYPE + QCLASS
                finalResponse.insert(finalResponse.end(), query.begin() + sizeof(DNSHeader), query.begin() + qOffset);

                // Build CNAME records from the chain
                for (const auto &cnamePair : cnameChain)
                {
                    // Encode source domain name
                    std::string src = cnamePair.first;
                    if (!src.empty() && src.back() != '.')
                        src += '.';

                    std::string::size_type pos = 0;
                    while (pos < src.size() && src[pos] != '\0')
                    {
                        std::string::size_type dotPos = src.find('.', pos);
                        if (dotPos == std::string::npos)
                            break;
                        uint8_t len = dotPos - pos;
                        finalResponse.push_back(len);
                        for (std::string::size_type i = 0; i < len; ++i)
                            finalResponse.push_back(src[pos + i]);
                        pos = dotPos + 1;
                    }
                    finalResponse.push_back(0); // null terminator

                    // TYPE = CNAME (5)
                    finalResponse.push_back(0);
                    finalResponse.push_back(5);
                    // CLASS = IN (1)
                    finalResponse.push_back(0);
                    finalResponse.push_back(1);
                    // TTL = 300 seconds
                    finalResponse.push_back(0);
                    finalResponse.push_back(0);
                    finalResponse.push_back(1);
                    finalResponse.push_back(0x2C);

                    // Encode target domain name and calculate RDLENGTH
                    std::vector<uint8_t> targetEncoded;
                    std::string tgt = cnamePair.second;
                    if (!tgt.empty() && tgt.back() != '.')
                        tgt += '.';

                    pos = 0;
                    while (pos < tgt.size() && tgt[pos] != '\0')
                    {
                        std::string::size_type dotPos = tgt.find('.', pos);
                        if (dotPos == std::string::npos)
                            break;
                        uint8_t len = dotPos - pos;
                        targetEncoded.push_back(len);
                        for (std::string::size_type i = 0; i < len; ++i)
                            targetEncoded.push_back(tgt[pos + i]);
                        pos = dotPos + 1;
                    }
                    targetEncoded.push_back(0); // null terminator

                    // RDLENGTH
                    uint16_t rdlen = targetEncoded.size();
                    finalResponse.push_back((rdlen >> 8) & 0xFF);
                    finalResponse.push_back(rdlen & 0xFF);

                    // RDATA (target domain)
                    finalResponse.insert(finalResponse.end(), targetEncoded.begin(), targetEncoded.end());
                }

                // Add A records from final response
                tmpOffset = answerStartOffset;
                for (int j = 0; j < anCount && tmpOffset < response.size(); ++j)
                {
                    size_t rrStart = tmpOffset;
                    // Skip name field
                    if ((response[tmpOffset] & 0xC0) == 0xC0)
                        tmpOffset += 2;
                    else
                    {
                        while (tmpOffset < response.size() && response[tmpOffset] != 0)
                            tmpOffset += response[tmpOffset] + 1;
                        tmpOffset++;
                    }
                    if (tmpOffset + 10 > response.size())
                        break;

                    size_t typeOffset = tmpOffset;
                    uint16_t recType = ntohs(*reinterpret_cast<const uint16_t *>(&response[tmpOffset]));
                    tmpOffset += 2; // TYPE
                    uint16_t recClass = ntohs(*reinterpret_cast<const uint16_t *>(&response[tmpOffset]));
                    tmpOffset += 2; // CLASS
                    uint32_t recTTL = ntohl(*reinterpret_cast<const uint32_t *>(&response[tmpOffset]));
                    tmpOffset += 4; // TTL
                    uint16_t recRdlen = ntohs(*reinterpret_cast<const uint16_t *>(&response[tmpOffset]));
                    tmpOffset += 2;
                    size_t rdataOffset = tmpOffset;
                    size_t rrEnd = tmpOffset + recRdlen;

                    if (recType == 1 || recType == 28) // A or AAAA record
                    {
                        // Reconstruct A/AAAA record with correct NAME field (pointing to last CNAME target)
                        std::string aRecordName = cnameChain.empty() ? domain : cnameChain.back().second;
                        if (!aRecordName.empty() && aRecordName.back() != '.')
                            aRecordName += '.';

                        // Encode the name
                        std::string::size_type pos = 0;
                        while (pos < aRecordName.size() && aRecordName[pos] != '\0')
                        {
                            std::string::size_type dotPos = aRecordName.find('.', pos);
                            if (dotPos == std::string::npos)
                                break;
                            uint8_t len = dotPos - pos;
                            finalResponse.push_back(len);
                            for (std::string::size_type i = 0; i < len; ++i)
                                finalResponse.push_back(aRecordName[pos + i]);
                            pos = dotPos + 1;
                        }
                        finalResponse.push_back(0); // null terminator

                        // Add TYPE, CLASS, TTL
                        finalResponse.push_back((recType >> 8) & 0xFF);
                        finalResponse.push_back(recType & 0xFF);
                        finalResponse.push_back((recClass >> 8) & 0xFF);
                        finalResponse.push_back(recClass & 0xFF);
                        finalResponse.push_back((recTTL >> 24) & 0xFF);
                        finalResponse.push_back((recTTL >> 16) & 0xFF);
                        finalResponse.push_back((recTTL >> 8) & 0xFF);
                        finalResponse.push_back(recTTL & 0xFF);

                        // Add RDLENGTH and RDATA
                        finalResponse.push_back((recRdlen >> 8) & 0xFF);
                        finalResponse.push_back(recRdlen & 0xFF);
                        finalResponse.insert(finalResponse.end(),
                                             response.begin() + rdataOffset,
                                             response.begin() + rrEnd);
                    }
                    tmpOffset = rrEnd;
                }

                return finalResponse;
            }
            if (!nextCNAME.empty())
            {
                // Follow CNAME
                currentDomain = nextCNAME;
                // Start again from root servers
                nextServers.clear();
                for (const char *ip : rootServers)
                    nextServers.push_back(ip);
                found = true;
                break;
            }
            // If no A or CNAME, try authority/additional
            std::vector<std::string> nsList = extractAuthorityServers(response);
            std::map<std::string, std::string> ipMap = extractAdditionalIPs(response);
            if (!nsList.empty())
            {
                nextServers.clear();
                for (const std::string &ns : nsList)
                {
                    if (ipMap.count(ns))
                        nextServers.push_back(ipMap[ns]);
                }
                if (nextServers.empty())
                {
                    // Resolve NS records if no glue
                    for (const std::string &ns : nsList)
                    {
                        std::string nsTrim = ns;
                        if (!nsTrim.empty() && nsTrim.back() == '.')
                            nsTrim.pop_back();
                        auto nsQuery = buildQuery(nsTrim);
                        auto nsResp = recursiveResolve(nsQuery, port);
                        std::string nsIP = extractIPv4(nsResp);
                        if (!nsIP.empty())
                            nextServers.push_back(nsIP);
                    }
                }
                if (!nextServers.empty())
                {
                    found = true;
                    break;
                }
            }
        }
        if (!found)
            break;
    }
    return lastResponse;
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

std::string extractIPv6(const std::vector<uint8_t> &response)
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

        if (type == 28 && classCode == 1 && rdLength == 16)
        {
            char ipbuf[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &response[offset], ipbuf, sizeof(ipbuf));
            return std::string(ipbuf);
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

uint16_t extractQueryType(const std::vector<uint8_t> &query)
{
    size_t pos = sizeof(DNSHeader);
    // Skip domain name
    while (pos < query.size() && query[pos] != 0)
        pos += query[pos] + 1;
    pos++; // skip null terminator

    if (pos + 2 <= query.size())
    {
        uint16_t qtype = ntohs(*(uint16_t *)&query[pos]);
        return qtype;
    }
    return 1; // Default to A record
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
        else if (type == 28 && rdlength == 16) // AAAA record (IPv6)
        {
            char ipv6buf[INET6_ADDRSTRLEN];
            if (inet_ntop(AF_INET6, &response[offset], ipv6buf, sizeof(ipv6buf)))
            {
                chain.push_back(std::string(ipv6buf) + " (AAAA)");
            }
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