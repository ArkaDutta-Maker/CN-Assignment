#include <iostream>
#include <iomanip>
#include <thread>
#include <chrono>
#include <map>
#include "dns_cache_ui.h"
#include "dns_utils.h"
static void clearTopLines(int lines)
{

    std::cout << "\033[H"; // Move to top
    for (int i = 0; i < lines; ++i)
        std::cout << "\033[2K\033[E"; // Clear line and move to next
    std::cout << "\033[H";            // Move back to top
    std::cout.flush();
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
        auto snapshot = cache->snapshot();
        clearTopLines(snapshot.size() + 6);

        std::cout << "+------------------------------+------------------------------+--------+-----------+\n";
        std::cout << "| Domain                       | Resolved / Chain             | TTL(s) | Status     |\n";
        std::cout << "+------------------------------+------------------------------+--------+------------+\n";

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
            auto chain = extractResolutionChain(entry.second.response);

            std::string status =
                (ttl > 30) ? "\033[32mActive\033[0m" : (ttl > 5) ? "\033[33mExpiring\033[0m"
                                                                 : "\033[31mCritical\033[0m";

            for (size_t i = 0; i < chain.size(); ++i)
            {
                std::string displayChain = (i == 0) ? chain[i] : "↳ " + chain[i];

                std::cout << "| " << std::setw(30) << std::left << (i == 0 ? domain : "")
                          << "| " << std::setw(30) << std::left << displayChain
                          << "| " << std::setw(6) << std::left << (i == 0 ? std::to_string(ttl) : "")
                          << "| " << std::setw(10) << std::left << (i == 0 ? status : "")
                          << " |\n";
            }
        }

        // Expired entries
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
                      << "| " << std::setw(30) << std::left << "-"
                      << "| " << std::setw(6) << std::left << "0"
                      << "| " << std::setw(10) << std::left << "\033[31m❌Expired\033[0m"
                      << " |\n";
            ++it;
        }

        if (!anyActive && expiredDisplay.empty())
        {
            std::cout << "| " << std::setw(82) << std::left << "No active cache entries"
                      << " |\n";
        }

        std::cout << "+------------------------------+------------------------------+--------+------------+\n";

        std::cout.flush();
        std::this_thread::sleep_for(1s);
    }
}
