#include "common.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <map>
#include <chrono>
#include <thread>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <algorithm>

static constexpr int PORT = 9090;

// Wait for ACK or NACK for SR/GBN
bool wait_for_ack(int fd, uint8_t &seq, int timeoutMs, bool &isAck)
{
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);

    timeval tv{};
    tv.tv_sec = timeoutMs / 1000;
    tv.tv_usec = (timeoutMs % 1000) * 1000;

    int r = select(fd + 1, &rfds, nullptr, nullptr, &tv);
    if (r <= 0)
        return false;

    uint8_t ack[3];
    if (!read_exact(fd, ack, sizeof(ack)))
        return false;

    seq = ack[1];
    isAck = (ack[2] == 1);
    return true;
}

int main()
{
    std::string path, flow;
    int payloadLen, crcBits, timeoutMs, windowSize = 1;

    std::cout << "[Sender] Enter bitstream file: ";
    std::cin >> path;
    std::cout << "[Sender] Payload size per frame: ";
    std::cin >> payloadLen;
    std::cout << "[Sender] CRC width (8/10/16/32): ";
    std::cin >> crcBits;
    std::cout << "[Sender] ACK timeout (ms): ";
    std::cin >> timeoutMs;
    std::cout << "[Sender] Flow control (stop | gbn | sr): ";
    std::cin >> flow;

    if (flow == "gbn" || flow == "sr")
    {
        std::cout << "[Sender] Window size: ";
        std::cin >> windowSize;
    }

    if (!is_supported_crc(crcBits) || payloadLen <= 0 || windowSize <= 0)
        return 1;

    // Load bitstream
    std::ifstream fin(path);
    std::string raw((std::istreambuf_iterator<char>(fin)), std::istreambuf_iterator<char>());
    std::string bits;
    std::copy_if(raw.begin(), raw.end(), std::back_inserter(bits),
                 [](char c)
                 { return c == '0' || c == '1'; });
    if (bits.empty())
    {
        std::cerr << "No bits found\n";
        return 1;
    }

    // Prepare frames
    struct FrameInfo
    {
        Frame frame;
        std::vector<uint8_t> wire;
        bool acked = false;
        std::chrono::steady_clock::time_point lastSent;
    };
    std::vector<FrameInfo> frames;
    uint8_t seq = 0;
    for (size_t i = 0; i < bits.size(); i += payloadLen, ++seq)
    {
        std::string chunk = bits.substr(i, payloadLen);
        Frame f{};
        fill_header(f.hdr, SENDER_ADDR, RECEIVER_ADDR, (uint16_t)chunk.size(), seq);
        f.payload = chunk;
        f.crc = compute_crc(bytes_for_crc(f.hdr, f.payload), crcBits);

        std::vector<uint8_t> wire;
        append_header(wire, f.hdr);
        append_payload(wire, f.payload);
        append_crc(wire, f.crc);

        frames.push_back({f, wire});
    }

    // Connect to receiver
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (connect(fd, (sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("connect");
        return 1;
    }

    std::cout << "[Sender] Connected. Starting transmission...\n";

    if (flow == "stop")
    {
        for (auto &f : frames)
        {
            bool acked = false;
            while (!acked)
            {
                write_exact(fd, f.wire.data(), f.wire.size());
                uint8_t ackSeq;
                bool isAck;
                if (wait_for_ack(fd, ackSeq, timeoutMs, isAck) && isAck && ackSeq == f.frame.hdr.seq)
                {
                    acked = true;
                    std::cout << "[Sender] ACK received seq=" << (int)ackSeq << "\n";
                }
                else
                {
                    std::cout << "[Sender] Timeout seq=" << (int)f.frame.hdr.seq << " → retransmit\n";
                }
            }
        }
    }
    else if (flow == "gbn")
    {
        size_t base = 0;
        size_t nextFrame = 0;

        while (base < frames.size())
        {
            // Send frames in window
            while (nextFrame < base + windowSize && nextFrame < frames.size())
            {
                write_exact(fd, frames[nextFrame].wire.data(), frames[nextFrame].wire.size());
                frames[nextFrame].lastSent = std::chrono::steady_clock::now();
                std::cout << "[Sender] Sent seq=" << (int)frames[nextFrame].frame.hdr.seq << "\n";
                ++nextFrame;
            }

            uint8_t ackSeq;
            bool isAck;
            if (wait_for_ack(fd, ackSeq, timeoutMs, isAck) && isAck)
            {
                if (ackSeq >= base && ackSeq < base + windowSize)
                {
                    size_t shift = ackSeq - base + 1;
                    std::cout << "[Sender] Cumulative ACK received seq=" << (int)ackSeq << "\n";
                    base += shift;
                }
            }
            else
            {
                std::cout << "[Sender] Timeout window starting seq=" << (int)frames[base].frame.hdr.seq << " → retransmit\n";
                nextFrame = base;
            }
        }
    }

    else if (flow == "sr")
    {
        size_t nextFrame = 0;
        std::vector<bool> acked(frames.size(), false);

        while (nextFrame < frames.size())
        {
            auto now = std::chrono::steady_clock::now();
            for (size_t i = 0; i < frames.size(); ++i)
            {
                if (acked[i])
                    continue;

                bool neverSent = (frames[i].lastSent == std::chrono::steady_clock::time_point{});

                long long elapsedMs = neverSent ? 0
                                                : std::chrono::duration_cast<std::chrono::milliseconds>(now - frames[i].lastSent).count();

                if (neverSent || elapsedMs >= timeoutMs)
                {
                    write_exact(fd, frames[i].wire.data(), frames[i].wire.size());
                    frames[i].lastSent = now;
                    if (neverSent)
                        std::cout << "[Sender] Initial send seq=" << (int)frames[i].frame.hdr.seq << "\n";
                    else
                        std::cout << "[Sender] Timeout retransmit seq=" << (int)frames[i].frame.hdr.seq << " (elapsed=" << elapsedMs << " ms)\n";
                }
            }

            uint8_t ackSeq;
            bool isAck;
            if (wait_for_ack(fd, ackSeq, timeoutMs, isAck))
            {
                if (ackSeq >= frames.size())
                    continue;

                if (isAck)
                {
                    acked[ackSeq] = true;
                    std::cout << "[Sender] ACK received seq=" << (int)ackSeq << "\n";
                }
                else
                {
                    write_exact(fd, frames[ackSeq].wire.data(), frames[ackSeq].wire.size());
                    frames[ackSeq].lastSent = std::chrono::steady_clock::now();
                    std::cout << "[Sender] NACK seq=" << (int)ackSeq << " → retransmit\n";
                }
            }

            // Advance nextFrame pointer
            while (nextFrame < frames.size() && acked[nextFrame])
                ++nextFrame;
        }
    }

    std::cout << "[Sender] Transmission complete.\n";
    close(fd);
    return 0;
}
