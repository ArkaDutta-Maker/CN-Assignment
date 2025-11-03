#include "DNSMsg.h"
#include <iostream>
#include <thread>
#include <unordered_map>
#include <vector>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

#define PORT 8053
#define BACKLOG 10

class DNSServer
{
    int listen_fd = -1;
    std::unordered_map<std::string, std::string> table;

public:
    DNSServer()
    {
        table["www.warp.com"] = "1.1.1.1";
        table["www.google.com"] = "8.8.8.8";
        table["localhost"] = "127.0.0.1";
    }

    void start()
    {
        listen_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (listen_fd < 0)
        {
            perror("socket");
            exit(1);
        }

        int opt = 1;
        setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(PORT);

        if (bind(listen_fd, (sockaddr *)&addr, sizeof(addr)) < 0)
        {
            perror("bind");
            exit(1);
        }
        if (listen(listen_fd, BACKLOG) < 0)
        {
            perror("listen");
            exit(1);
        }

        std::cout << "[DNS] listening on 0.0.0.0:" << PORT << "\n";

        while (true)
        {
            sockaddr_in cli{};
            socklen_t len = sizeof(cli);
            int client = accept(listen_fd, (sockaddr *)&cli, &len);
            if (client < 0)
            {
                perror("accept");
                continue;
            }
            std::thread(&DNSServer::handleClient, this, client).detach();
        }
    }

private:
    void handleClient(int client_fd)
    {
        // Read 2-byte length (network order)
        uint8_t lenbuf[2];
        ssize_t r = recvAll(client_fd, lenbuf, 2);
        if (r != 2)
        {
            close(client_fd);
            return;
        }
        uint16_t msglen = (lenbuf[0] << 8) | lenbuf[1];

        std::vector<uint8_t> req(msglen);
        r = recvAll(client_fd, req.data(), msglen);
        if (r != msglen)
        {
            close(client_fd);
            return;
        }

        DNSMessage reqMsg;
        if (!reqMsg.decodeRequest(req))
        {
            close(client_fd);
            return;
        }

        std::cout << "[QUERY] id=" << reqMsg.id << " name=" << reqMsg.qname << " type=" << reqMsg.qtype << "\n";

        DNSMessage resp;
        resp.id = reqMsg.id;
        // set response flags: QR=1 (response), RD copied, RA=1, RCODE set appropriately
        uint16_t flags = 0;
        // copy RD bit from request
        if (reqMsg.flags & 0x0100)
            flags |= 0x0100;
        // set QR and RA
        flags |= 0x8000; // QR = 1 (response)
        flags |= 0x0080; // RA = 1
        resp.flags = flags;

        resp.qdcount = 1;
        resp.qname = reqMsg.qname;
        resp.qtype = reqMsg.qtype;
        resp.qclass = reqMsg.qclass;
        auto it = table.find(reqMsg.qname);
        if (it != table.end() && reqMsg.qtype == 1 && reqMsg.qclass == 1)
        {
            resp.answer_ip = it->second;
            resp.ancount = 1;
            resp.flags |= 0; // RCODE 0
        }
        else
        {
            // name error (RCODE=3) if no such name
            resp.ancount = 0;
            resp.flags |= 3; // rcode = 3 (Name Error)
        }

        std::vector<uint8_t> out = resp.encode();
        uint16_t outlen = htons(static_cast<uint16_t>(out.size()));
        // send 2-byte length then data
        sendAll(client_fd, reinterpret_cast<uint8_t *>(&outlen), 2);
        sendAll(client_fd, out.data(), out.size());

        close(client_fd);
    }

    // helper: read exactly n bytes
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
};

int main()
{
    DNSServer s;
    s.start();
    return 0;
}
