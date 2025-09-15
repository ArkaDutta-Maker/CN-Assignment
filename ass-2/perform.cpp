#include <bits/stdc++.h>
#include <chrono>
#include "client.cpp"

using namespace std;
using namespace chrono;

void measurePerformance(const string &serverIp, int port, const string &file,
                        const string &scheme, FlowControlType flowType, int windowSize)
{
    string bits = Client::read_bits_file(file);
    if (bits.empty())
    {
        cerr << "Input file has no bits!\n";
        return;
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

    Client client(serverIp, port);

    cout << "=== Testing " << (flowType == FlowControlType::STOP_AND_WAIT ? "Stop-and-Wait" : flowType == FlowControlType::GO_BACK_N ? "Go-Back-N"
                                                                                                                                     : "Selective Repeat")
         << " (Window Size = " << windowSize << ") ===\n";

    auto start = steady_clock::now();
    client.sendFrames(payloads, scheme, flowType, windowSize);
    auto end = steady_clock::now();

    auto duration_ms = duration_cast<milliseconds>(end - start).count();
    cout << "[Performance] Total time: " << duration_ms << " ms\n";
    cout << "[Performance] Throughput: "
         << (payloads.size() * chunk_size * 8.0) / (duration_ms / 1000.0) / 1e6
         << " Mbps\n";
    cout << "===========================================\n\n";
}

int main()
{
    string serverIp = "127.0.0.1";
    int port = 8080;
    string inputFile = "msg.bits";
    string scheme = "checksum16";

    measurePerformance(serverIp, port, inputFile, scheme, FlowControlType::STOP_AND_WAIT, 1);
    measurePerformance(serverIp, port, inputFile, scheme, FlowControlType::GO_BACK_N, 4);
    measurePerformance(serverIp, port, inputFile, scheme, FlowControlType::SELECTIVE_REPEAT, 4);

    return 0;
}
