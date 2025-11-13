#include "dns_cache_ui.h"
#include <iostream>
#include <iomanip>
#include <thread>
#include <chrono>

static void clearScreen()
{
    std::cout << "\033[2J\033[H"; // ANSI escape code to clear terminal
}

static int timeLeft(const std::chrono::steady_clock::time_point &expiry)
{
    auto now = std::chrono::steady_clock::now();
    auto diff = std::chrono::duration_cast<std::chrono::seconds>(expiry - now).count();
    return diff > 0 ? diff : 0;
}

void runCacheUI(DNSCache *cache)
{
    using namespace std::chrono_literals;
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
        if (snapshot.empty())
        {
            std::cout << "| " << std::setw(54) << std::left << "No active cache entries"
                      << "|\n";
        }
        else
        {
            for (auto &entry : snapshot)
            {
                std::string domain = entry.first;
                int ttl = timeLeft(entry.second.expiry);
                std::string status;
                if (ttl > 30)
                    status = "\033[32mActive\033[0m"; // green
                else if (ttl > 0)
                    status = "\033[33mExpiring\033[0m"; // yellow
                else
                    status = "\033[31mExpired\033[0m"; // red

                std::cout << "| " << std::setw(30) << std::left << domain
                          << "| " << std::setw(10) << std::left << ttl
                          << "| " << std::setw(10) << std::left << status
                          << "|\n";
            }
        }

        std::cout << "+-------------------------------------------------------------+\n";
        std::this_thread::sleep_for(1s);
    }
}
