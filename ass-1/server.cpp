#include <bits/stdc++.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "common.h"

using namespace std;
#define PAYLOAD_SIZE 64
class Server
{
    int listenfd{-1};
    sockaddr_in addr{};

public:
    Server(int port)
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
        cout << "[Server] Listening on port " << port << " ...\n";
    }

    ~Server()
    {
        if (listenfd >= 0)
            close(listenfd);
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
        cout << "[Server] Client connected.\n";

        string buf;
        char tmp[8 * PAYLOAD_SIZE];
        ssize_t n;
        while ((n = recv(fd, tmp, sizeof(tmp), 0)) > 0)
        {
            buf.append(tmp, tmp + n);
            if (n < (ssize_t)sizeof(tmp))
                break;
        }
        if (n < 0)
            perror("recv");

        size_t nl = buf.find('\n');
        if (nl == string::npos)
        {
            cerr << "Malformed payload (no header newline)\n";
            return;
        }
        string header = buf.substr(0, nl);
        string body = trim01(buf.substr(nl + 1));

        unordered_map<string, string> H;

        {
            stringstream ss(header);
            string kv;
            while (getline(ss, kv, ';'))
            {
                auto p = kv.find('=');
                if (p != string::npos)
                {
                    string k = kv.substr(0, p);
                    string v = kv.substr(p + 1);
                    auto trim = [](string &x)
                    {
                        while (!x.empty() && isspace((unsigned char)x.back()))
                            x.pop_back();
                        size_t i = 0;
                        while (i < x.size() && isspace((unsigned char)x[i]))
                            ++i;
                        x = x.substr(i);
                    };
                    trim(k);
                    trim(v);
                    H[k] = v;
                }
            }
        }

        string scheme = H.count("scheme") ? H["scheme"] : "";
        string client_ip = H.count("client_ip") ? H["client_ip"] : "";

        // string injected = H.count("injected") ? H["injected"] : "0";
        string etype = H.count("error_type") ? H["error_type"] : "none";
        string data_len = H.count("data_len") ? H["data_len"] : "?";
        // cout << body << "\n";
        cout << "[Server] Header: " << header << "\n";
        cout << "[Server] Body bits length: " << body.size() << "\n";
        cout << "[Server] Client ip: " << client_ip << "\n";
        bool ok = false;
        if (scheme == "checksum16")
        {
            ok = checksum16_verify(body);
        }
        else if (is_crc_scheme(scheme))
        {
            ok = crc_verify_codeword(body, crc_generators().at(scheme));
        }
        else
        {
            cerr << "[Server] Unknown scheme.\n";
        }

        cout << "[Server] Validation: " << (ok ? "ACCEPT (no error detected)" : "REJECT (error detected)") << "\n";
        cout << "[Server] Meta:error_type=" << etype << "\n";
        string ack = (ok ? "ACCEPT (no error detected)" : "REJECT (error detected)");
        send(fd, ack.c_str(), ack.size(), 0);
        cout << "\nACK sent\n";
        close(fd);
    }
};

static void usage()
{
    cerr << "Usage: ./Server <port>\n";
}

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        usage();
        return 1;
    }
    int port = stoi(argv[1]);
    Server r(port);
    // Serve one message per run (simple lab demo). Re-run to test again.
    while (true)
        r.serve_once();
    return 0;
}
