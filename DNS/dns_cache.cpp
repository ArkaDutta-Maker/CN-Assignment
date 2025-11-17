#include "dns_cache.h"
#include <iostream>

void DNSCache::store(const std::string &key, const std::vector<uint8_t> &resp, uint32_t ttl)
{
    std::lock_guard<std::mutex> lock(mtx);
    cache[key] = {resp, std::chrono::steady_clock::now() + std::chrono::seconds(ttl)};
}

bool DNSCache::get(const std::string &key, std::vector<uint8_t> &resp)
{
    std::lock_guard<std::mutex> lock(mtx);
    auto it = cache.find(key);
    if (it == cache.end())
        return false;
    if (std::chrono::steady_clock::now() > it->second.expiry)
    {
        cache.erase(it);
        return false;
    }
    resp = it->second.response;
    return true;
}

void DNSCache::storeNS(const std::string &tld, const std::vector<std::string> &nameservers,
                       const std::map<std::string, std::string> &glueIPs, uint32_t ttl)
{
    std::lock_guard<std::mutex> lock(nsMtx);
    NSRecord record;
    record.nameservers = nameservers;
    record.glueIPs = glueIPs;
    record.expiry = std::chrono::steady_clock::now() + std::chrono::seconds(ttl);
    nsCache[tld] = record;

    std::cout << "[NS Cache] Stored TLD: " << tld << " with " << nameservers.size()
              << " nameservers, " << glueIPs.size() << " glue records, TTL: " << ttl << "s\n";
}

bool DNSCache::getNS(const std::string &tld, std::vector<std::string> &nameservers,
                     std::map<std::string, std::string> &glueIPs)
{
    std::lock_guard<std::mutex> lock(nsMtx);
    auto it = nsCache.find(tld);
    if (it == nsCache.end())
        return false;

    if (std::chrono::steady_clock::now() > it->second.expiry)
    {
        std::cout << "[NS Cache] Expired TLD: " << tld << "\n";
        nsCache.erase(it);
        return false;
    }

    nameservers = it->second.nameservers;
    glueIPs = it->second.glueIPs;
    std::cout << "[NS Cache Hit] TLD: " << tld << " with " << nameservers.size()
              << " nameservers\n";
    return true;
}

std::unordered_map<std::string, CacheEntry> DNSCache::snapshot()
{
    std::lock_guard<std::mutex> lock(mtx);
    return {cache.begin(), cache.end()};
}
