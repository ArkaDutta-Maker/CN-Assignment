#ifndef DNS_UTILS_H
#define DNS_UTILS_H

#include <vector>
#include <string>
#include <cstdint>

#pragma pack(push, 1)
struct DNSHeader
{
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};
#pragma pack(pop)

std::vector<uint8_t> queryUpstream(const std::vector<uint8_t> &query,
                                   const std::string &dnsServerIP,
                                   int port);

uint32_t extractTTL(const std::vector<uint8_t> &response);
std::string extractDomainName(const std::vector<uint8_t> &query);
std::string extractIPv4(const std::vector<uint8_t> &response);

#endif
