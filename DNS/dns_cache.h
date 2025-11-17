#ifndef DNS_CACHE_H
#define DNS_CACHE_H

#include <unordered_map>
#include <vector>
#include <string>
#include <chrono>
#include <mutex>
#include <map>

struct CacheEntry
{
    std::vector<uint8_t> response;
    std::chrono::steady_clock::time_point expiry;
};

struct NSRecord
{
    std::vector<std::string> nameservers;
    std::map<std::string, std::string> glueIPs;
    std::chrono::steady_clock::time_point expiry;
};

class DNSCache
{

    std::unordered_map<std::string, CacheEntry> cache;
    std::unordered_map<std::string, NSRecord> nsCache;
    std::mutex mtx;
    std::mutex nsMtx;

public:
    void store(const std::string &key, const std::vector<uint8_t> &resp, uint32_t ttl);
    bool get(const std::string &key, std::vector<uint8_t> &resp);

    // NS cache methods
    void storeNS(const std::string &tld, const std::vector<std::string> &nameservers,
                 const std::map<std::string, std::string> &glueIPs, uint32_t ttl);
    bool getNS(const std::string &tld, std::vector<std::string> &nameservers,
               std::map<std::string, std::string> &glueIPs);

    // New methods for UI
    std::unordered_map<std::string, CacheEntry> snapshot();
};

#endif
