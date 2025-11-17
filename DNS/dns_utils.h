#ifndef DNS_UTILS_H
#define DNS_UTILS_H

#include <vector>
#include <string>
#include <cstdint>
#include <map>
#include <unordered_map>

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

// Recursively resolve a DNS query starting from root servers
std::vector<uint8_t> recursiveResolve(const std::vector<uint8_t> &query, int port = 53);

uint32_t extractTTL(const std::vector<uint8_t> &response);
std::string extractDomainName(const std::vector<uint8_t> &query);
uint16_t extractQueryType(const std::vector<uint8_t> &query);
std::string extractIPv4(const std::vector<uint8_t> &response);
std::string extractIPv6(const std::vector<uint8_t> &response);
std::string extractRecordType(const std::vector<uint8_t> &response);
std::vector<std::string> extractResolutionChain(const std::vector<uint8_t> &response);
std::vector<std::string> extractAuthorityServers(const std::vector<uint8_t> &response);
std::map<std::string, std::string> extractAdditionalIPs(const std::vector<uint8_t> &response);
std::vector<uint8_t> buildQuery(const std::string &domain);
std::vector<uint8_t> buildQuery(const std::string &domain, uint16_t qtype);
#endif
