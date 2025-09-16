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
#include <random>

static constexpr int PORT = 9090;

std::random_device rd;
std::mt19937 gen(rd());

bool should_simulate_error(double prob)
{
    std::uniform_real_distribution<> dis(0.0, 1.0);
    return dis(gen) < prob;
}

bool wait_for_ack(int fd, uint8_t &seq, int timeoutMs, bool &isAck, double ack_error_prob, double ack_delay_prob)
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

    if (should_simulate_error(ack_delay_prob))
        std::this_thread::sleep_for(std::chrono::milliseconds(timeoutMs + 10));

    uint8_t ack[3];
    if (!read_exact(fd, ack, sizeof(ack)))
        return false;

    if (should_simulate_error(ack_error_prob))
        return false;

    seq = ack[1];
    isAck = (ack[2] == 1);
    return true;
}

int main()
{
    std::string path, flow;
    int payloadLen, crcBits, timeoutMs, windowSize = 1;
    double errorProb, delayProb;

    std::cout << "[Sender] Enter bitstream file: ";
    std::cin >> path;
    std::cout << "[Sender] Payload size per frame(in Bytes): ";
    std::cin >> payloadLen;
    payloadLen *= 8;
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

    std::cout << "[Sender] Error probability (0.0 - 0.5): ";
    std::cin >> errorProb;
    std::cout << "[Sender] Delay probability (0.0 - 0.5): ";
    std::cin >> delayProb;

    if (!is_supported_crc(crcBits) || payloadLen <= 0 || windowSize <= 0)
        return 1;

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

    size_t totalTransmissions = 0;
    auto startTime = std::chrono::steady_clock::now();

    std::vector<long long> rttList;

    if (flow == "stop")
    {
        for (auto &f : frames)
        {
            bool acked = false;
            while (!acked)
            {
                auto sendTime = std::chrono::steady_clock::now();
                write_exact(fd, f.wire.data(), f.wire.size());
                ++totalTransmissions;

                uint8_t ackSeq;
                bool isAck;
                if (wait_for_ack(fd, ackSeq, timeoutMs, isAck, errorProb, delayProb) && isAck && ackSeq == f.frame.hdr.seq)
                {
                    acked = true;
                    auto ackTime = std::chrono::steady_clock::now();
                    long long durationMs = std::chrono::duration_cast<std::chrono::milliseconds>(ackTime - sendTime).count();
                    rttList.push_back(durationMs);

                    std::cout << "[Sender] ACK received seq=" << (int)ackSeq
                              << " (RTT=" << durationMs << " ms)\n";
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
            while (nextFrame < base + windowSize && nextFrame < frames.size())
            {
                auto sendTime = std::chrono::steady_clock::now();
                write_exact(fd, frames[nextFrame].wire.data(), frames[nextFrame].wire.size());
                frames[nextFrame].lastSent = sendTime;
                ++totalTransmissions;
                std::cout << "[Sender] Sent seq=" << (int)frames[nextFrame].frame.hdr.seq << "\n";
                ++nextFrame;
            }

            uint8_t ackSeq;
            bool isAck;
            if (wait_for_ack(fd, ackSeq, timeoutMs, isAck, errorProb, delayProb) && isAck)
            {
                if (ackSeq >= base && ackSeq < base + windowSize)
                {
                    auto ackTime = std::chrono::steady_clock::now();
                    long long durationMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                                               ackTime - frames[ackSeq].lastSent)
                                               .count();
                    rttList.push_back(durationMs);

                    std::cout << "[Sender] Cumulative ACK received seq=" << (int)ackSeq
                              << " (RTT=" << durationMs << " ms)\n";

                    size_t shift = ackSeq - base + 1;
                    base += shift;
                }
            }
            else
            {
                std::cout << "[Sender] Timeout window starting seq=" << (int)frames[base].frame.hdr.seq
                          << " → retransmit\n";
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
                    frames[i].lastSent = std::chrono::steady_clock::now();
                    write_exact(fd, frames[i].wire.data(), frames[i].wire.size());
                    ++totalTransmissions;

                    if (neverSent)
                        std::cout << "[Sender] Initial send seq=" << (int)frames[i].frame.hdr.seq << "\n";
                    else
                        std::cout << "[Sender] Timeout retransmit seq=" << (int)frames[i].frame.hdr.seq << "\n";
                }
            }

            uint8_t ackSeq;
            bool isAck;
            if (wait_for_ack(fd, ackSeq, timeoutMs, isAck, errorProb, delayProb))
            {
                if (ackSeq >= frames.size())
                    continue;

                if (isAck)
                {
                    auto ackTime = std::chrono::steady_clock::now();
                    long long durationMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                                               ackTime - frames[ackSeq].lastSent)
                                               .count();
                    rttList.push_back(durationMs);

                    acked[ackSeq] = true;
                    std::cout << "[Sender] ACK received seq=" << (int)ackSeq
                              << " (RTT=" << durationMs << " ms)\n";
                }
                else
                {
                    write_exact(fd, frames[ackSeq].wire.data(), frames[ackSeq].wire.size());
                    frames[ackSeq].lastSent = std::chrono::steady_clock::now();
                    ++totalTransmissions;
                    std::cout << "[Sender] NACK seq=" << (int)ackSeq << " → retransmit\n";
                }
            }

            while (nextFrame < frames.size() && acked[nextFrame])
                ++nextFrame;
        }
    }

    // Final RTT summary
    long long totalRtt = 0;
    for (auto rtt : rttList)
        totalRtt += rtt;

    double avgRtt = rttList.empty() ? 0.0 : static_cast<double>(totalRtt) / rttList.size();

    auto endTime = std::chrono::steady_clock::now();
    auto durationMs = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();
    double efficiency = (double)frames.size() / totalTransmissions;

    std::cout << "\n[Summary]\n";
    std::cout << "Total Frames: " << frames.size() << "\n";
    std::cout << "Total Transmissions: " << totalTransmissions << "\n";
    std::cout << "Total Time: " << durationMs << " ms\n";
    std::cout << "Efficiency (useful frames / total transmissions): " << efficiency << "\n";
    std::cout << "Average Propagation Delay (RTT): " << avgRtt << " ms\n";

    double durationSec = durationMs / 1000.0;      // convert ms to seconds
    double totalBits = frames.size() * payloadLen; // total useful bits sent

    double throughputMbps = totalBits / durationSec / 1e6;        // bits/sec -> Mbps
    double effectiveThroughputMbps = throughputMbps * efficiency; // account for retransmissions

    std::cout << "Raw Throughput: " << throughputMbps << " Mbps\n";
    std::cout << "Effective Throughput: " << effectiveThroughputMbps << " Mbps\n";
}
