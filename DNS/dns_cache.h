#ifndef DNS_CACHE_H
#define DNS_CACHE_H

#include <unordered_map>
#include <vector>
#include <string>
#include <chrono>
#include <mutex>
struct CacheEntry
{
    std::vector<uint8_t> response;
    std::chrono::steady_clock::time_point expiry;
};
class DNSCache
{

    std::unordered_map<std::string, CacheEntry> cache;
    std::mutex mtx;

public:
    void store(const std::string &key, const std::vector<uint8_t> &resp, uint32_t ttl);
    bool get(const std::string &key, std::vector<uint8_t> &resp);

    // New methods for UI
    std::unordered_map<std::string, CacheEntry> snapshot();
};

#endif
