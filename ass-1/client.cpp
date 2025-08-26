#include <bits/stdc++.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "common.h"
#include "error_injector.h"
#include <netinet/ether.h>

using namespace std;

class Client
{
    int sockfd{-1};
    sockaddr_in serv{};
    string ip;
    int port;
    struct ifreq ifr{};

public:
    Client(const string &ip, int port)
    {
        this->ip = ip;
        this->port = port;
        sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
        if (sockfd < 0)
        {
            perror("socket");
            exit(1);
        }
        serv.sin_family = AF_INET;
        serv.sin_port = htons(port);
        if (inet_pton(AF_INET, ip.c_str(), &serv.sin_addr) <= 0)
        {
            perror("inet_pton");
            exit(1);
        }
        if (connect(sockfd, (sockaddr *)&serv, sizeof(serv)) < 0)
        {
            perror("connect");
            exit(1);
        }
    }

    ~Client()
    {
        if (sockfd >= 0)
            close(sockfd);
    }

    static string read_bits_file(const string &path)
    {
        ifstream f(path);
        if (!f)
        {
            perror("open file");
            exit(1);
        }
        string all, line;
        while (getline(f, line))
            all += line;
        return trim01(all);
    }

    static string make_codeword(const string &scheme, const string &bits)
    {
        if (scheme == "checksum16")
            return checksum16_append(bits);
        if (is_crc_scheme(scheme))
            return crc_make_codeword(bits, crc_generators().at(scheme));
        cerr << "Unknown scheme: " << scheme << "\n";
        exit(1);
    }

    bool send_payload(const string &scheme, string &codeword,
                      bool injected, ErrorType etype, const string &data_len_bits)
    {

        ostringstream hdr;

        struct sockaddr_in client_addr;
        socklen_t len = sizeof(client_addr);
        getsockname(this->sockfd, (struct sockaddr *)&client_addr, &len);
        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
        int client_port = ntohs(client_addr.sin_port);

        unsigned char *mac = get_mac_address(this->sockfd, this->ifr, "eth0");
        string sender_mac = ether_ntoa((struct ether_addr *)mac);

        string receiver_mac = "00:00:00:00:00:00";
        hdr << "scheme=" << scheme << ";receiver_mac=" << receiver_mac
            << ";receiver_ip=" << this->ip << ";receiver_port=" << this->port << ";client_mac=" << sender_mac << ";client_port=" << to_string(client_port) << ";error_type=" << (injected ? errorTypeName(etype) : "none")
            << ";data_len=" << data_len_bits
            << "\n";

        string header = hdr.str();

        string payload = header + codeword;

        ssize_t n = send(sockfd, payload.c_str(), payload.size(), 0);
        if (n < 0)
        {
            perror("send");
            exit(1);
        }
        cout << "[Client] Sent " << n << " bytes\n";
        cout << "[Client] Header: " << header;
        // cout << "[Client] Codeword: "
        //      << codeword << "\n";
        //  << (codeword.size() > 128 ? "..." : "") << "\n";

        char buffer[1024] = {0};
        int valread = recv(sockfd, buffer, 1024, 0);
        if (valread > 0)
        {
            buffer[valread] = '\0';
            cout << "Received ACK from server: " << buffer << endl;
            string s(buffer);
            if (s.find("ACCEPT") != string::npos)
            {
                return true;
            }
        }
        return false;
    }
};

static void usage()
{
    cerr << "Usage:\n"
            "  ./client <server_ip> <port> <input_bits_file> --scheme <checksum16|crc8|crc10|crc16|crc32>\n"
            "            [--inject yes|no] [--inject-prob 0..1]\n\n";
}

int main(int argc, char **argv)
{
    // if (argc < 7)
    // {
    //     usage();
    //     return 1;
    // }

    string ip = argv[1];
    int port = stoi(argv[2]);
    string file = argv[3];

    string scheme;
    bool inject = false;
    double inject_prob = 0.5;
    int inject_scheme = -1;
    bool random = false;

    for (int i = 4; i < argc; ++i)
    {
        string a = argv[i];
        if (a == "--scheme" && i + 1 < argc)
        {
            scheme = argv[++i];
        }
        if (a == "--inject" && i + 1 < argc)
        {
            string v = argv[++i];
            inject = (v == "yes" || v == "y" || v == "true" || v == "1");
        }
        if (a == "--inject-prob" && i + 1 < argc)
        {
            inject_prob = stod(argv[++i]);
            inject_prob = max(0.0, min(1.0, inject_prob));
        }
        if (a == "--injectscheme")
        {
            inject_scheme = stoi(argv[++i]);
        }
        if (a == "--random" && i + 1 < argc)
        {
            string v = argv[++i];
            random = (v == "yes" || v == "y" || v == "true" || v == "1");
        }
    }

    if (scheme.empty())
    {
        usage();
        return 1;
    }
    if (scheme != "checksum16" && !is_crc_scheme(scheme))
    {
        cerr << "Invalid scheme\n";
        return 1;
    }
    if (random)
    {
        while (true)
        {
            srand((unsigned)time(nullptr));

            string data_bits = Client::read_bits_file(file);
            if (data_bits.empty())
            {
                cerr << "Input has no bits 0/1\n";
                return 1;
            }
            string codeword = Client::make_codeword(scheme, data_bits);
            int len = -1;
            if (scheme == "checksum16")
            {
                ErrorInjector inj(len);
                ErrorType etype = ErrorType::TWO_ISOLATED;

                codeword = inj.inject(codeword, etype);
                Client s(ip, port);

                if (s.send_payload(scheme, codeword, true, etype, to_string(data_bits.size())))
                {
                    cout << scheme << "\n"
                         << codeword << "\n";
                    break;
                }
            }
            else
            {
                if (scheme == "crc8")
                {
                    len = 9;
                }
                if (scheme == "crc10")
                {
                    len = 11;
                }
                if (scheme == "crc16")
                {
                    len = 17;
                }
                if (scheme == "crc32")
                {
                    len = 33;
                }
                ErrorInjector inj(len);
                ErrorType etype = ErrorType::BURST;

                codeword = inj.inject(codeword, etype);
                Client s(ip, port);

                if (s.send_payload(scheme, codeword, true, etype, to_string(data_bits.size())))
                {
                    cout << scheme << "\n"
                         << codeword << "\n";
                    break;
                }
            }
        }
        return 0;
    }
    string data_bits = Client::read_bits_file(file);
    if (data_bits.empty())
    {
        cerr << "Input has no bits 0/1\n";
        return 1;
    }

    string codeword = Client::make_codeword(scheme, data_bits);

    ErrorInjector inj;
    bool actually_injected = false;
    ErrorType etype = static_cast<ErrorType>(inject_scheme);

    if (inject)
    {
        if (inject_scheme == -1)
            etype = inj.randomType();
        codeword = inj.inject(codeword, etype);
        actually_injected = true;
    }

    try
    {
        Client s(ip, port);
        s.send_payload(scheme, codeword, actually_injected, etype, to_string(data_bits.size()));
    }
    catch (...)
    {
        cerr << "Client failed\n";
        return 1;
    }

    return 0;
}
