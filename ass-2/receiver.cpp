#include <bits/stdc++.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/ether.h>
#include <net/if.h>
#include "frame.h"
#include "error_injector.h"

using namespace std;

#define MAX_FRAME_SIZE 1500

class Receiver
{
    int listenfd{-1};
    sockaddr_in addr{};
    struct ifreq ifr{};

public:
    Receiver(int port)
    {
        listenfd = socket(AF_INET, SOCK_STREAM, 0);
        if (listenfd < 0)
        {
            perror("socket");
            exit(1);
        }

        int opt = 1;
        if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
        {
            perror("setsockopt");
            exit(1);
        }

        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(port);

        if (bind(listenfd, (sockaddr *)&addr, sizeof(addr)) < 0)
        {
            perror("bind");
            exit(1);
        }
        if (listen(listenfd, 1) < 0)
        {
            perror("listen");
            exit(1);
        }

        cout << "[Receiver] Listening on port " << port << " ...\n";
    }

    ~Receiver()
    {
        if (listenfd >= 0)
            close(listenfd);
    }

    vector<unsigned char> Recv(int fd)
    {
        vector<unsigned char> buf(MAX_FRAME_SIZE);
        ssize_t n = recv(fd, buf.data(), buf.size(), 0);
        if (n <= 0)
        {
            if (n < 0)
                perror("recv");
            return {};
        }
        buf.resize(n);
        return buf;
    }

    bool Check(const Frame &f, const string &scheme)
    {
        return f.verify(scheme);
    }

    void Send(int fd, bool ok, uint8_t seqNo)
    {
        string ack = ok ? "ACK:" + to_string(seqNo) : "NAK:" + to_string(seqNo);
        send(fd, ack.c_str(), ack.size(), 0);
        cout << "[Receiver] Sent " << (ok ? "ACK" : "NAK") << " for seq=" << int(seqNo) << "\n";
    }

    void serve_once()
    {
        sockaddr_in cli{};
        socklen_t clen = sizeof(cli);
        int fd = accept(listenfd, (sockaddr *)&cli, &clen);
        if (fd < 0)
        {
            perror("accept");
            return;
        }
        cout << "[Receiver] Client connected.\n";

        auto raw = Recv(fd);
        if (raw.empty())
        {
            close(fd);
            return;
        }

        if (raw.size() < 12)
        {
            cerr << "[Receiver] Frame too short!\n";
            close(fd);
            return;
        }

        Frame f;
        memcpy(f.srcMAC, raw.data(), 6);
        memcpy(f.destMAC, raw.data() + 6, 6);
        f.length = ntohs(*(uint16_t *)(raw.data() + 12));
        f.seqNo = raw[14];
        f.payload.assign(raw.begin() + 15, raw.begin() + 15 + f.length);
        f.fcs = ntohl(*(uint32_t *)(raw.data() + 15 + f.length));

        string scheme = "checksum16";
        cout << "[Receiver] Received frame seq=" << int(f.seqNo) << ", payload bytes=" << f.payload.size() << "\n";

        bool ok = Check(f, scheme);
        cout << "[Receiver] Validation: " << (ok ? "ACCEPT" : "REJECT") << "\n";

        Send(fd, ok, f.seqNo);
        close(fd);
    }
};

static void usage()
{
    cerr << "Usage: ./Receiver <port>\n";
}

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        usage();
        return 1;
    }

    int port = stoi(argv[1]);
    Receiver r(port);

    while (true)
        r.serve_once();

    return 0;
}
