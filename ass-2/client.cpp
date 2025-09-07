#include <bits/stdc++.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <net/if.h>
#include <netinet/ether.h>
#include "frame.h"
#include "error_injector.h"
using namespace std;

class Client
{
    int sockfd{-1};
    sockaddr_in serv{};
    string ip;
    int port;

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

    static void channel(Frame &f, double errorProb = 0.1)
    {
        int delay_ms = rand() % 500;
        this_thread::sleep_for(chrono::milliseconds(delay_ms));

        if ((rand() / (double)RAND_MAX) < errorProb)
        {
            ErrorInjector inj;
            string bits = Frame::bytesToBits(f.payload);
            string corrupted_bits = inj.inject(bits, ErrorType::BURST);
            vector<unsigned char> newPayload;
            for (size_t i = 0; i < corrupted_bits.size(); i += 8)
            {
                unsigned char b = 0;
                for (int j = 0; j < 8 && i + j < corrupted_bits.size(); ++j)
                    b |= (corrupted_bits[i + j] - '0') << (7 - j);
                newPayload.push_back(b);
            }
            f.payload = newPayload;
        }
    }

    bool sendFrame(Frame &f, const string &scheme)
    {
        Timer t(1000);
        t.startTimer();

        while (true)
        {
            vector<unsigned char> frame_bytes;
            frame_bytes.insert(frame_bytes.end(), f.srcMAC, f.srcMAC + 6);
            frame_bytes.insert(frame_bytes.end(), f.destMAC, f.destMAC + 6);
            uint16_t len_net = htons(f.payload.size());
            frame_bytes.push_back(len_net >> 8);
            frame_bytes.push_back(len_net & 0xFF);
            frame_bytes.push_back(f.seqNo);
            frame_bytes.insert(frame_bytes.end(), f.payload.begin(), f.payload.end());
            uint32_t fcs_net = htonl(f.fcs);
            frame_bytes.push_back((fcs_net >> 24) & 0xFF);
            frame_bytes.push_back((fcs_net >> 16) & 0xFF);
            frame_bytes.push_back((fcs_net >> 8) & 0xFF);
            frame_bytes.push_back(fcs_net & 0xFF);

            ssize_t n = send(sockfd, frame_bytes.data(), frame_bytes.size(), 0);
            if (n < 0)
            {
                perror("send");
                return false;
            }
            cout << "[Client] Sent frame seq=" << int(f.seqNo) << ", " << n << " bytes\n";

            fd_set readfds;
            FD_ZERO(&readfds);
            FD_SET(sockfd, &readfds);
            timeval tv;
            tv.tv_sec = t.getTimeout() / 1000;
            tv.tv_usec = (t.getTimeout() % 1000) * 1000;

            int rv = select(sockfd + 1, &readfds, NULL, NULL, &tv);
            if (rv > 0 && FD_ISSET(sockfd, &readfds))
            {
                char ack_buf[64];
                int val = recv(sockfd, ack_buf, sizeof(ack_buf) - 1, 0);
                if (val > 0)
                {
                    ack_buf[val] = '\0';
                    string ack(ack_buf);
                    if (ack.find("ACK") != string::npos)
                    {
                        cout << "[Client] Received ACK for seq=" << int(f.seqNo) << "\n";
                        return true;
                    }
                }
            }

            cout << "[Client] Timeout! Retransmitting frame seq=" << int(f.seqNo) << "\n";
            t.startTimer();
        }
    }

    void sendFrames(vector<vector<unsigned char>> &payloads, const string &scheme,
                    FlowControlType flowType, int windowSize = 1)
    {
        struct ifreq ifr{};
        unsigned char *mac = get_mac_address(sockfd, ifr, "eth0");
        unsigned char destMAC[6] = {0};

        uint8_t seq = 0;

        if (flowType == FlowControlType::STOP_AND_WAIT)
        {
            for (auto &payload : payloads)
            {
                Frame f(mac, destMAC, seq++, payload, scheme);
                Client::channel(f);
                sendFrame(f, scheme);
            }
        }
        else if (flowType == FlowControlType::GO_BACK_N)
        {
            size_t i = 0;
            while (i < payloads.size())
            {
                size_t winEnd = min(i + windowSize, payloads.size());
                vector<Frame> window;
                for (size_t j = i; j < winEnd; ++j)
                    window.emplace_back(mac, destMAC, seq++, payloads[j], scheme);

                for (auto &f : window)
                {
                    Client::channel(f);
                    send(sockfd, f.payload.data(), f.payload.size(), 0);
                }

                char ack_buf[64];
                int val = recv(sockfd, ack_buf, sizeof(ack_buf) - 1, 0);
                if (val > 0)
                {
                    ack_buf[val] = '\0';
                    string ack(ack_buf);
                    if (ack.find("ACK") != string::npos)
                    {
                        i += window.size();
                        continue;
                    }
                }
            }
        }
        else if (flowType == FlowControlType::SELECTIVE_REPEAT)
        {
            size_t i = 0;
            map<uint8_t, Frame> window;
            map<uint8_t, bool> acked;
            while (i < payloads.size() || !window.empty())
            {
                while (window.size() < windowSize && i < payloads.size())
                {
                    Frame f(mac, destMAC, seq++, payloads[i], scheme);
                    Client::channel(f);
                    sendFrame(f, scheme);
                    window[f.seqNo] = f;
                    acked[f.seqNo] = false;
                    i++;
                }

                char ack_buf[64];
                int val = recv(sockfd, ack_buf, sizeof(ack_buf) - 1, 0);
                if (val > 0)
                {
                    ack_buf[val] = '\0';
                    string ack(ack_buf);
                    if (ack.find("ACK") != string::npos)
                    {
                        uint8_t ackSeq = stoi(ack.substr(4));
                        if (window.count(ackSeq))
                            acked[ackSeq] = true;
                    }
                }

                for (auto &[seqNum, f] : window)
                    if (!acked[seqNum])
                        sendFrame(f, scheme);

                for (auto it = window.begin(); it != window.end();)
                {
                    if (acked[it->first])
                        it = window.erase(it);
                    else
                        ++it;
                }
            }
        }
    }
};

static void usage()
{
    cerr << "Usage:\n"
            "  ./client <server_ip> <port> <input_bits_file> --scheme <checksum16|crc8|crc10|crc16|crc32> "
            "--flow <stop|gbn|sr> [--window N]\n";
}

int main(int argc, char **argv)
{
    if (argc < 7)
    {
        usage();
        return 1;
    }

    string ip = argv[1];
    int port = stoi(argv[2]);
    string file = argv[3];
    string scheme = argv[5];
    string flow = argv[7];
    int windowSize = 1;
    if (argc >= 10)
        windowSize = stoi(argv[9]);

    string bits = Client::read_bits_file(file);
    if (bits.empty())
    {
        cerr << "Input file has no bits!\n";
        return 1;
    }

    vector<vector<unsigned char>> payloads;
    size_t chunk_size = 46;
    for (size_t i = 0; i < bits.size(); i += chunk_size)
    {
        vector<unsigned char> payload;
        for (size_t j = 0; j < chunk_size && i + j < bits.size(); j += 8)
        {
            unsigned char b = 0;
            for (int k = 0; k < 8 && i + j + k < bits.size(); ++k)
                b |= (bits[i + j + k] - '0') << (7 - k);
            payload.push_back(b);
        }
        payloads.push_back(payload);
    }

    Client client(ip, port);
    FlowControlType flowType = FlowControlType::STOP_AND_WAIT;
    if (flow == "gbn")
        flowType = FlowControlType::GO_BACK_N;
    else if (flow == "sr")
        flowType = FlowControlType::SELECTIVE_REPEAT;

    client.sendFrames(payloads, scheme, flowType, windowSize);

    return 0;
}
