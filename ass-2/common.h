#pragma once
#include <bits/stdc++.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <netinet/in.h>
#include <net/if_arp.h>

using namespace std;

// ---------- Bitstring helpers ----------
inline string trim01(const string &s)
{
    string t;
    t.reserve(s.size());
    for (char c : s)
        if (c == '0' || c == '1')
            t.push_back(c);
    return t;
}

inline string u16_to_bits(uint16_t x)
{
    string b;
    b.reserve(16);
    for (int i = 15; i >= 0; --i)
        b.push_back(((x >> i) & 1) + '0');
    return b;
}

inline uint16_t bits_to_u16(const string &b)
{
    uint16_t v = 0;
    for (char c : b)
        v = (v << 1) | (c == '1');
    return v;
}

inline string checksum16_append(const string &data_bits)
{
    string padded = data_bits;
    size_t rem = padded.size() % 16;
    if (rem != 0)
        padded.append(16 - rem, '0');

    uint32_t sum = 0;
    for (size_t i = 0; i < padded.size(); i += 16)
    {
        uint16_t val = bits_to_u16(padded.substr(i, 16));
        sum += val;
        while (sum >> 16)
            sum = (sum & 0xFFFF) + (sum >> 16);
    }

    uint16_t csum = static_cast<uint16_t>(~sum);
    string checksum = u16_to_bits(csum);

    return padded + checksum;
}
unsigned char *get_mac_address(int sockfd, struct ifreq &ifr, const char *iface)
{
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) == -1)
    {
        perror("ioctl");
        exit(1);
    }
    return (unsigned char *)ifr.ifr_hwaddr.sa_data;
}
inline bool checksum16_verify(const string &full_bits_in)
{
    string s = full_bits_in;
    size_t rem = s.size() % 16;
    if (rem != 0)
        s.append(16 - rem, '0');

    uint32_t sum = 0;
    for (size_t i = 0; i < s.size(); i += 16)
    {
        uint16_t val = bits_to_u16(s.substr(i, 16));
        sum += val;
        while (sum >> 16)
            sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return static_cast<uint16_t>(sum) == 0xFFFF;
}

inline string crc_divide(string bits, const string &gen)
{
    int m = (int)gen.size();
    for (int i = 0; i <= (int)bits.size() - m; ++i)
    {
        if (bits[i] == '1')
        {
            for (int j = 0; j < m; ++j)
            {
                bits[i + j] = (bits[i + j] == gen[j]) ? '0' : '1';
            }
        }
    }
    return bits.substr(bits.size() - (m - 1));
}

inline string crc_make_codeword(const string &data_bits, const string &gen)
{
    string appended = data_bits + string(gen.size() - 1, '0');
    string rem = crc_divide(appended, gen);
    return data_bits + rem;
}

inline bool crc_verify_codeword(const string &codeword, const string &gen)
{
    string rem = crc_divide(codeword, gen);
    return rem.find('1') == string::npos;
}

inline const unordered_map<string, string> &crc_generators()
{
    static const unordered_map<string, string> m = {
        {"crc8", "100000111"},          // x^8 + x^7 + x^6 + x^4 + x^2 + 1
        {"crc10", "11000110011"},       // x^10 + x^9 + x^5 + x^4 + x + 1
        {"crc16", "11000000000000101"}, // x^16 + x^15 + x^2 + 1
        {"crc32", "100000100110000010001110110110111"}};
    return m;
}

inline bool is_crc_scheme(const string &s)
{
    auto &m = crc_generators();
    return m.find(s) != m.end();
}
