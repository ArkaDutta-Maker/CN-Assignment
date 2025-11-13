#include "dns_cache_ui.h"
#include <iostream>
#include <iomanip>
#include <thread>
#include <chrono>
#include <map>

static void clearScreen()
{
    std::cout << "\033[2J\033[H"; // ANSI escape: clear screen
}

static int timeLeft(const std::chrono::steady_clock::time_point &expiry)
{
    auto now = std::chrono::steady_clock::now();
    auto diff = std::chrono::duration_cast<std::chrono::seconds>(expiry - now).count();
    return diff;
}

void runCacheUI(DNSCache *cache)
{
    using namespace std::chrono_literals;

    std::map<std::string, std::pair<std::chrono::steady_clock::time_point, int>> expiredDisplay;

    while (true)
    {
        clearScreen();
        std::cout << "+-------------------------------------------------------------+\n";
        std::cout << "|                LIVE DNS CACHE MONITOR (Auto Refresh)        |\n";
        std::cout << "+-------------------------------------------------------------+\n";
        std::cout << "| " << std::setw(30) << std::left << "Domain"
                  << "| " << std::setw(10) << std::left << "TTL(s)"
                  << "| " << std::setw(10) << std::left << "Status"
                  << "|\n";
        std::cout << "+-------------------------------------------------------------+\n";

        auto snapshot = cache->snapshot();
        bool anyActive = false;

        for (auto &entry : snapshot)
        {
            std::string domain = entry.first;
            int ttl = timeLeft(entry.second.expiry);

            if (ttl <= 0)
            {
                expiredDisplay[domain] = {std::chrono::steady_clock::now(), 2};
                continue;
            }

            anyActive = true;
            std::string status = (ttl > 30)  ? "\033[32mActive\033[0m"
                                 : (ttl > 5) ? "\033[33mExpiring\033[0m"
                                             : "\033[31mCritical\033[0m";

            std::cout << "| " << std::setw(30) << std::left << domain
                      << "| " << std::setw(10) << std::left << ttl
                      << "| " << std::setw(10) << std::left << status
                      << "|\n";
        }

        for (auto it = expiredDisplay.begin(); it != expiredDisplay.end();)
        {
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                               std::chrono::steady_clock::now() - it->second.first)
                               .count();
            if (elapsed > it->second.second)
            {
                it = expiredDisplay.erase(it);
                continue;
            }

            std::cout << "| " << std::setw(30) << std::left << it->first
                      << "| " << std::setw(10) << std::left << "0"
                      << "| \033[31m❌ Expired\033[0m   |\n";
            ++it;
        }

        if (!anyActive && expiredDisplay.empty())
            std::cout << "| " << std::setw(54) << std::left << "No active cache entries"
                      << "|\n";

        std::cout << "+-------------------------------------------------------------+\n";

        std::this_thread::sleep_for(1s);
    }
}
