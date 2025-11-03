#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <arpa/inet.h>
#include <stdexcept>
#include <cstring>

// Minimal DNS header helpers (RFC 1035)
#pragma pack(push, 1)
struct RawDNSHeader
{
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};
#pragma pack(pop)

inline void write16(std::vector<uint8_t> &buf, uint16_t v)
{
    buf.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    buf.push_back(static_cast<uint8_t>(v & 0xFF));
}
inline void write32(std::vector<uint8_t> &buf, uint32_t v)
{
    buf.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
    buf.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
    buf.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    buf.push_back(static_cast<uint8_t>(v & 0xFF));
}

inline uint16_t read16(const uint8_t *p)
{
    return static_cast<uint16_t>((p[0] << 8) | p[1]);
}
inline uint32_t read32(const uint8_t *p)
{
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) |
           (static_cast<uint32_t>(p[3]));
}

// Encode domain like "www.example.com" -> 3www7example3com0
inline void encodeName(std::vector<uint8_t> &out, const std::string &name)
{
    if (name.empty())
    {
        out.push_back(0);
        return;
    }
    size_t start = 0;
    while (start < name.size())
    {
        size_t dot = name.find('.', start);
        if (dot == std::string::npos)
            dot = name.size();
        size_t len = dot - start;
        if (len > 63)
            throw std::runtime_error("label too long");
        out.push_back(static_cast<uint8_t>(len));
        for (size_t i = 0; i < len; ++i)
            out.push_back(static_cast<uint8_t>(name[start + i]));
        start = dot + 1;
    }
    out.push_back(0); // terminator
}

// Read name starting at offset; returns name and advances offset past the name
inline std::string decodeName(const std::vector<uint8_t> &buf, size_t &offset)
{
    std::string name;
    bool first = true;
    while (offset < buf.size())
    {
        uint8_t len = buf[offset++];
        if (len == 0)
            break;
        if ((len & 0xC0) == 0xC0)
        {
            // compression pointer: two bytes total; read second byte and compute pointer
            if (offset >= buf.size())
                return name;
            uint8_t next = buf[offset++];
            uint16_t ptr = static_cast<uint16_t>(((len & 0x3F) << 8) | next);
            size_t tmp = ptr; // pointer is an offset into the message
            // recursively decode from pointer once
            std::string tail = decodeName(buf, tmp);
            if (!name.empty() && !tail.empty())
                name += ".";
            name += tail;
            break;
        }
        else
        {
            // label
            if (!first)
                name += '.';
            first = false;
            if (offset + len > buf.size())
                return name; // safety
            for (size_t i = 0; i < len; ++i)
            {
                name.push_back(static_cast<char>(buf[offset++]));
            }
        }
    }
    return name;
}
