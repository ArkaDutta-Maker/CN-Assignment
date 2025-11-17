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
#include <regex>
static std::string stripAnsi(const std::string &s)
{
    static const std::regex ansi_re("\\x1B\\[[0-9;]*[A-Za-z]");
    return std::regex_replace(s, ansi_re, "");
}
static std::string fitWidth(const std::string &s, size_t width)
{
    std::string plain = stripAnsi(s);
    if (plain.size() > width)
    {
        // Truncate visible part, keep ANSI codes
        size_t vis = 0, i = 0;
        std::string out;
        while (i < s.size() && vis < width - 1)
        {
            if (s[i] == '\033' && s[i + 1] == '[')
            {
                size_t esc_end = i + 2;
                while (esc_end < s.size() && ((s[esc_end] >= '0' && s[esc_end] <= '9') || s[esc_end] == ';'))
                    ++esc_end;
                if (esc_end < s.size())
                    ++esc_end;
                out += s.substr(i, esc_end - i);
                i = esc_end;
            }
            else
            {
                out += s[i++];
                ++vis;
            }
        }
        out += "…";
        // Pad if needed
        while (stripAnsi(out).size() < width)
            out += ' ';
        return out;
    }
    std::string out = s;
    while (stripAnsi(out).size() < width)
        out += ' ';
    return out;
}

void runCacheUI(DNSCache *cache)
{
    using namespace std::chrono_literals;
    std::map<std::string, std::pair<std::chrono::steady_clock::time_point, int>> expiredDisplay;

    constexpr int W_DOMAIN = 28, W_TYPE = 7, W_VALUE = 39, W_TTL = 7, W_STATUS = 10;
    const int totalWidth = W_DOMAIN + W_TYPE + W_VALUE + W_TTL + W_STATUS + 6 * 3 + 1;
    const std::string sep = "+" + std::string(W_DOMAIN + 2, '-') + "+" + std::string(W_TYPE + 2, '-') + "+" + std::string(W_VALUE + 2, '-') + "+" + std::string(W_TTL + 2, '-') + "+" + std::string(W_STATUS + 2, '-') + "+\n";

    while (true)
    {
        auto snapshot = cache->snapshot();
        clearTopLines(snapshot.size() + 8);

        std::cout << sep;
        std::cout << "| " << fitWidth("Domain", W_DOMAIN) << " | "
                  << fitWidth("Type", W_TYPE) << " | "
                  << fitWidth("Value", W_VALUE) << " | "
                  << fitWidth("TTL(s)", W_TTL) << " | "
                  << fitWidth("Status", W_STATUS) << " |\n";
        std::cout << sep;

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

            if (chain.empty())
            {
                std::cout << "| " << fitWidth(domain, W_DOMAIN) << " | "
                          << fitWidth("-", W_TYPE) << " | "
                          << fitWidth("-", W_VALUE) << " | "
                          << fitWidth(std::to_string(ttl), W_TTL) << " | "
                          << fitWidth(status, W_STATUS) << " |\n";
                continue;
            }

            for (size_t i = 0; i < chain.size(); ++i)
            {
                std::string type, value;

                auto pos = chain[i].find(": ");
                if (pos != std::string::npos)
                {
                    type = chain[i].substr(0, pos);
                    value = chain[i].substr(pos + 2);
                }
                else
                {
                    type = (i == chain.size() - 1) ? "A/AAAA" : "CNAME";
                    value = chain[i];
                }
                std::string hop = (i == 0 ? domain : "↳ " + value);
                std::cout << "| " << fitWidth(i == 0 ? domain : "", W_DOMAIN) << " | "
                          << fitWidth(type, W_TYPE) << " | "
                          << fitWidth(value, W_VALUE) << " | "
                          << fitWidth(i == 0 ? std::to_string(ttl) : "", W_TTL) << " | "
                          << fitWidth(i == 0 ? status : "", W_STATUS) << " |\n";
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
            std::cout << "| " << fitWidth(it->first, W_DOMAIN) << " | "
                      << fitWidth("-", W_TYPE) << " | "
                      << fitWidth("-", W_VALUE) << " | "
                      << fitWidth("0", W_TTL) << " | "
                      << fitWidth("\033[31m❌Expired\033[0m", W_STATUS) << " |\n";
            ++it;
        }

        if (!anyActive && expiredDisplay.empty())
        {
            std::string msg = fitWidth("No active cache entries", W_DOMAIN + W_TYPE + W_VALUE + W_TTL + W_STATUS + 6 * 3 + 1 - 6);
            std::cout << "| " << msg << "|\n";
        }

        std::cout << sep;
        std::cout.flush();
        std::this_thread::sleep_for(1s);
    }
}
