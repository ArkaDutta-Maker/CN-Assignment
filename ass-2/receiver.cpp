#include "common.h"
#include <iostream>
#include <thread>
#include <chrono>
#include <random>
#include <vector>
#include <map>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

static constexpr int PORT = 9090;

int main()
{
    int crcBits, windowSize = 1;
    std::string flow;

    std::cout << "[Receiver] CRC width: ";
    std::cin >> crcBits;
    if (!is_supported_crc(crcBits))
        return 1;
    std::cout << "[Receiver] Flow control (stop | gbn | sr): ";
    std::cin >> flow;
    if (flow == "gbn" || flow == "sr")
    {
        std::cout << "[Receiver] Window size: ";
        std::cin >> windowSize;
    }
    double drop_val;
    std::cout << "[Receiver] Drop Probability: ";
    std::cin >> drop_val;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> jitterMs(50, 300);       // jitter in ms
    std::uniform_real_distribution<float> dropProb(0.0f, 1.0f); // for drop simulation

    int srv = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (bind(srv, (sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("bind");
        return 1;
    }
    if (listen(srv, 1) < 0)
    {
        perror("listen");
        return 1;
    }
    std::cout << "[Receiver] Listening...\n";

    int fd = accept(srv, nullptr, nullptr);
    if (fd < 0)
    {
        perror("accept");
        return 1;
    }
    std::cout << "[Receiver] Connection established.\n";

    uint8_t expectedGbn = 0;
    uint8_t expectedSr = 0;
    std::map<uint8_t, std::string> srBuffer; // buffer for out-of-order SR frames

    while (true)
    {
        FrameHeader h;
        if (!read_exact(fd, &h, sizeof(h)))
        {
            std::cout << "[Receiver] Closed.\n";
            break;
        }
        uint16_t len = ntohs(h.length);

        std::string payload(len, '\0');
        if (!read_exact(fd, payload.data(), len))
            break;

        uint32_t wireCrcBE;
        if (!read_exact(fd, &wireCrcBE, sizeof(wireCrcBE)))
            break;
        uint32_t rxCrc = ntohl(wireCrcBE);

        auto bytes = bytes_for_crc(h, payload);
        uint32_t calc = compute_crc(bytes, crcBits);
        bool ok = ((rxCrc & ((crcBits == 32) ? 0xFFFFFFFFu : ((1u << crcBits) - 1u))) ==
                   (calc & ((crcBits == 32) ? 0xFFFFFFFFu : ((1u << crcBits) - 1u))));

        // apply jitter
        std::this_thread::sleep_for(std::chrono::milliseconds(jitterMs(gen)));

        // random drop simulation
        if (dropProb(gen) < drop_val)
        {
            ok = false;
            std::cout << "[Receiver] Random drop seq=" << (int)h.seq << "\n";
        }

        uint8_t seq = h.seq;

        if (flow == "stop")
        {
            if (ok)
            {
                uint8_t ack[3] = {0xAC, seq, 1};
                write_exact(fd, ack, sizeof(ack));
                std::cout << "[Receiver] ACK seq=" << (int)seq << "\n";
            }
            else
            {
                std::cout << "[Receiver] Dropped seq=" << (int)seq << "\n";
            }
        }
        else if (flow == "gbn")
        {
            if (ok && seq == expectedGbn)
            {
                std::cout << "[Receiver] Delivered seq=" << (int)seq << "\n";

                uint8_t ack[3] = {0xAC, seq, 1}; // ACK
                write_exact(fd, ack, sizeof(ack));
                std::cout << "[Receiver] Cumulative ACK seq=" << (int)seq << "\n";

                ++expectedGbn;
            }
            else
            {
                // Out-of-order frames are ignored, send ACK of last in-order received frame
                uint8_t ack[3] = {0xAC, (uint8_t)(expectedGbn - 1), 1};
                write_exact(fd, ack, sizeof(ack));
                std::cout << "[Receiver] Duplicate ACK seq=" << (int)(expectedGbn - 1) << " Seq Received:- " << (int)seq << " Expected Seq:- " << (int)expectedGbn << "\n";
            }
        }
        else if (flow == "sr")
        {
            if (ok)
            {
                if (srBuffer.find(seq) == srBuffer.end())
                {
                    srBuffer[seq] = payload;
                    std::cout << "[Receiver] Buffered seq=" << (int)seq << "\n";
                }

                uint8_t ack[3] = {0xAC, seq, 1};
                write_exact(fd, ack, sizeof(ack));
                std::cout << "[Receiver] ACK seq=" << (int)seq << "\n";

                // Deliver in-order frames
                while (srBuffer.count(expectedSr))
                {
                    std::cout << "[Receiver] Delivered seq=" << (int)expectedSr << "\n";
                    srBuffer.erase(expectedSr);
                    ++expectedSr;
                }
            }
            else
            {
                uint8_t nack[3] = {0xAC, seq, 0};
                write_exact(fd, nack, sizeof(nack));
                std::cout << "[Receiver] NACK seq=" << (int)seq << "\n";
            }
        }
    }
    close(fd);
    close(srv);
    return 0;
}