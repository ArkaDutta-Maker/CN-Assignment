#include "dns_cache.h"

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

std::unordered_map<std::string, CacheEntry> DNSCache::snapshot()
{
    std::lock_guard<std::mutex> lock(mtx);
    return {cache.begin(), cache.end()};
}
