#pragma once
#include "DNScommon.h"
#include <vector>
#include <string>
#include <cstring>
#include <arpa/inet.h>

// Minimal DNS message class supporting one question and one A answer
class DNSMessage
{
public:
    uint16_t id = 0;
    uint16_t flags = 0x0100; // default query flags
    uint16_t qdcount = 1;
    uint16_t ancount = 0;
    std::string qname;
    uint16_t qtype = 1;  // A
    uint16_t qclass = 1; // IN

    // For answer (A record)
    std::string answer_ip; // dotted form if present
    uint32_t ttl = 3600;

    // Encode into DNS wire bytes (header + question + answer if set)
    std::vector<uint8_t> encode() const
    {
        std::vector<uint8_t> out;
        // reserve estimate
        out.reserve(256);

        // Header (6 * 2 bytes)
        write16(out, id);
        write16(out, flags);
        write16(out, qdcount);
        write16(out, ancount);
        write16(out, 0); // nscount
        write16(out, 0); // arcount

        // Question
        encodeName(out, qname);
        write16(out, qtype);
        write16(out, qclass);

        // Answer (if present)
        if (ancount > 0 && !answer_ip.empty())
        {
            // NAME (we'll repeat the full qname)
            encodeName(out, qname);
            write16(out, 1); // TYPE A
            write16(out, 1); // CLASS IN
            write32(out, ttl);
            write16(out, 4); // RDLENGTH
            // RDATA
            struct in_addr a;
            if (inet_pton(AF_INET, answer_ip.c_str(), &a) != 1)
            {
                // invalid ip - write zeros
                out.push_back(0);
                out.push_back(0);
                out.push_back(0);
                out.push_back(0);
            }
            else
            {
                uint8_t *p = reinterpret_cast<uint8_t *>(&a.s_addr);
                // note: inet_pton gives network order; append bytes in network order
                out.push_back(p[0]);
                out.push_back(p[1]);
                out.push_back(p[2]);
                out.push_back(p[3]);
            }
        }

        return out;
    }

    // Decode basic request (header + question). This can also decode responses but we only need requests on server side.
    bool decodeRequest(const std::vector<uint8_t> &in)
    {
        if (in.size() < 12)
            return false;
        id = read16(in.data());
        flags = read16(in.data() + 2);
        qdcount = read16(in.data() + 4);
        ancount = read16(in.data() + 6);
        // nscount/arcount ignored
        size_t offset = 12;
        qname = decodeName(in, offset);
        if (offset + 4 > in.size())
            return false;
        qtype = read16(in.data() + offset);
        offset += 2;
        qclass = read16(in.data() + offset);
        offset += 2;
        return true;
    }
};
