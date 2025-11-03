#include "DNSMsg.h"
#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <vector>

#define PORT 8053

ssize_t recvAll(int fd, void *buf, size_t n)
{
    size_t off = 0;
    while (off < n)
    {
        ssize_t r = recv(fd, (char *)buf + off, n - off, 0);
        if (r <= 0)
            return r;
        off += r;
    }
    return off;
}
ssize_t sendAll(int fd, const void *buf, size_t n)
{
    size_t off = 0;
    while (off < n)
    {
        ssize_t s = send(fd, (const char *)buf + off, n - off, 0);
        if (s <= 0)
            return s;
        off += s;
    }
    return off;
}

int main()
{
    std::string domain;
    std::cout << "Domain to query: ";
    std::getline(std::cin, domain);
    if (domain.empty())
        return 0;

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in serv{};
    serv.sin_family = AF_INET;
    serv.sin_port = htons(PORT);
    inet_pton(AF_INET, "127.0.0.1", &serv.sin_addr);

    if (connect(sock, (sockaddr *)&serv, sizeof(serv)) < 0)
    {
        perror("connect");
        return 1;
    }

    DNSMessage q;
    q.id = rand() & 0xFFFF;
    q.qname = domain;
    q.qtype = 1;
    q.qclass = 1;
    q.flags = 0x0100; // RD

    std::vector<uint8_t> raw = q.encode();
    uint16_t len16 = htons((uint16_t)raw.size());
    sendAll(sock, &len16, 2);
    sendAll(sock, raw.data(), raw.size());

    uint8_t lenbuf[2];
    if (recvAll(sock, lenbuf, 2) != 2)
    {
        close(sock);
        return 1;
    }
    uint16_t rlen = (lenbuf[0] << 8) | lenbuf[1];
    std::vector<uint8_t> resp(rlen);
    if (recvAll(sock, resp.data(), rlen) != rlen)
    {
        close(sock);
        return 1;
    }

    DNSMessage respMsg;
    // For simplicity reuse decodeRequest to extract header+question (ancount read via header)
    respMsg.decodeRequest(resp);
    uint16_t flags = read16(resp.data() + 2); // not available; decodeRequest didn't parse flags into variable - skip
    // Better: parse header directly
    uint16_t ancount = read16(resp.data() + 6);
    if (ancount > 0)
    {
        // find answer: decode question to advance offset
        size_t offset = 12;
        std::string qn = decodeName(resp, offset);
        offset += 4; // qtype + qclass
        // answer name
        std::string aname = decodeName(resp, offset);
        uint16_t atype = read16(resp.data() + offset);
        offset += 2;
        uint16_t aclass = read16(resp.data() + offset);
        offset += 2;
        uint32_t attl = read32(resp.data() + offset);
        offset += 4;
        uint16_t rdlen = read16(resp.data() + offset);
        offset += 2;
        if (atype == 1 && rdlen == 4)
        {
            char ipbuf[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, resp.data() + offset, ipbuf, sizeof(ipbuf));
            std::cout << "Answer: " << aname << " -> " << ipbuf << "\n";
        }
        else
        {
            std::cout << "Answer present but not A/4 bytes\n";
        }
    }
    else
    {
        std::cout << "No answers (rcode may indicate error)\n";
    }

    close(sock);
    return 0;
}
