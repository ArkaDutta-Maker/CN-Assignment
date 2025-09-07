
#include "common.h"
#include <bits/stdc++.h>

enum class FlowControlType
{
    STOP_AND_WAIT,
    GO_BACK_N,
    SELECTIVE_REPEAT
};

class Timer
{
    chrono::steady_clock::time_point start;
    int timeoutInterval;
    bool running;

public:
    Timer(int interval = 1000) : timeoutInterval(interval), running(false) {}
    void startTimer()
    {
        start = chrono::steady_clock::now();
        running = true;
    }
    int elapsed() { return running ? chrono::duration_cast<chrono::milliseconds>(chrono::steady_clock::now() - start).count() : 0; }
    void Timeout(int rtt) { timeoutInterval = (3 * timeoutInterval + rtt) / 4; }
    bool expired() { return running && elapsed() >= timeoutInterval; }
    int getTimeout() const { return timeoutInterval; }
};

class Frame
{
public:
    unsigned char srcMAC[6];
    unsigned char destMAC[6];
    uint16_t length;
    uint8_t seqNo;
    vector<unsigned char> payload;
    uint32_t fcs;
    Timer timer;
    Frame()
    {
    }
    Frame(const unsigned char src[6], const unsigned char dest[6], uint8_t seq,
          const vector<unsigned char> &data, const string &scheme)
        : seqNo(seq), payload(data), timer(1000)
    {
        memcpy(srcMAC, src, 6);
        memcpy(destMAC, dest, 6);
        length = payload.size();
        string bits = bytesToBits(payload);
        if (scheme == "checksum16")
            fcs = checksum16_append(bits).length();
        else if (is_crc_scheme(scheme))
            fcs = crc_make_codeword(bits, crc_generators().at(scheme)).length();
        else
        {
            cerr << "Unknown FCS scheme\n";
            exit(1);
        }
    }

    static string bytesToBits(const vector<unsigned char> &data)
    {
        string s;
        for (auto b : data)
            for (int i = 7; i >= 0; i--)
                s.push_back(((b >> i) & 1) + '0');
        return s;
    }

    bool verify(const string &scheme) const
    {
        string bits = bytesToBits(payload);
        if (scheme == "checksum16")
            return checksum16_verify(bits);
        if (is_crc_scheme(scheme))
            return crc_verify_codeword(bits, crc_generators().at(scheme));
        return false;
    }
};
