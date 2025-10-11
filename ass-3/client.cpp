#include "common.h"
#include <bits/stdc++.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <thread>
#include <mutex>
#include <atomic>
using namespace std;

static constexpr int PORT = 9090;
string server_ip = "127.0.0.1";

double P_persistent = 0.5;
int slot_ms = 50;
int ack_timeout_ms = 500;
int max_BEB_k = 10;
int frames_per_client = 5;
double collisionProb = 0.1;

atomic<long long> total_successful_bits{0};
atomic<long long> total_successful_frames{0};
atomic<long long> total_delay_us{0};
mutex stats_mtx;

bool is_channel_idle(int sock)
{
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(sock, &rfds);
    timeval tv{0, 0};
    int r = select(sock + 1, &rfds, NULL, NULL, &tv);
    return (r == 0);
}

void client_worker(int id, string server_ip, int frames_per_client)
{
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
    {
        cerr << "Socket creation failed\n";
        return;
    }

    sockaddr_in serv{};
    serv.sin_family = AF_INET;
    serv.sin_port = htons(PORT);
    inet_pton(AF_INET, server_ip.c_str(), &serv.sin_addr);

    if (connect(sock, (sockaddr *)&serv, sizeof(serv)) < 0)
    {
        cerr << "Connection failed for client " << id << "\n";
        close(sock);
        return;
    }

    ifstream fin("msg.bits");
    vector<string> frames;
    string line;
    while (getline(fin, line))
        if (!line.empty())
            frames.push_back(line);
    fin.close();

    mt19937 rng(random_device{}());
    uniform_real_distribution<double> prob(0.0, 1.0);

    for (int f = 0; f < frames_per_client; ++f)
    {
        string frame = frames[f % frames.size()];
        auto start_time = chrono::steady_clock::now();

        int attempt = 0;
        while (true)
        {
            if (!is_channel_idle(sock))
            {
                this_thread::sleep_for(chrono::milliseconds(slot_ms));
                continue;
            }

            if (prob(rng) > P_persistent)
            {
                this_thread::sleep_for(chrono::milliseconds(slot_ms));
                continue;
            }

            // Simulate random sender-side collision
            if (prob(rng) < collisionProb)
            {
                cerr << "[Client " << id << "] Local collision simulated.\n";
                this_thread::sleep_for(chrono::milliseconds(ack_timeout_ms));
                attempt++;
                int backoff = (1 << min(attempt, max_BEB_k)) * slot_ms;
                this_thread::sleep_for(chrono::milliseconds(backoff));
                continue;
            }

            send(sock, frame.c_str(), frame.size(), 0);

            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(sock, &rfds);
            timeval tv;
            tv.tv_sec = ack_timeout_ms / 1000;
            tv.tv_usec = (ack_timeout_ms % 1000) * 1000;
            int ret = select(sock + 1, &rfds, NULL, NULL, &tv);

            if (ret > 0)
            {
                char ackbuf[8];
                int n = recv(sock, ackbuf, sizeof(ackbuf), 0);
                if (n > 0 && string(ackbuf, n).find("ACK") != string::npos)
                {
                    auto end_time = chrono::steady_clock::now();
                    long long delay_us = chrono::duration_cast<chrono::microseconds>(end_time - start_time).count();
                    total_successful_frames++;
                    total_successful_bits += frame.size();
                    total_delay_us += delay_us;
                    break;
                }
            }

            attempt++;
            int backoff = (1 << min(attempt, max_BEB_k)) * slot_ms;
            this_thread::sleep_for(chrono::milliseconds(backoff));
        }
    }

    close(sock);
}

int main()
{
    int n_clients;
    cout << "Enter number of clients: ";
    cin >> n_clients;
    cout << "Frames per client: ";
    cin >> frames_per_client;
    cout << "p (persistence 0..1): ";
    cin >> P_persistent;
    cout << "slot time (ms): ";
    cin >> slot_ms;
    cout << "ACK timeout (ms): ";
    cin >> ack_timeout_ms;
    cout << "Max BEB exponent (k): ";
    cin >> max_BEB_k;
    cout << "Collision probability (sender-side): ";
    cin >> collisionProb;

    vector<thread> clients;
    auto start_all = chrono::steady_clock::now();

    atomic<bool> stop_monitor{false};
    thread monitor([&]()
                   {
        while (!stop_monitor) {
            this_thread::sleep_for(chrono::seconds(3));
            long long frames = total_successful_frames.load();
            long long bits = total_successful_bits.load();
            long long delayus = total_delay_us.load();
            double avg_delay_ms = frames ? (delayus / (double)frames / 1000.0) : 0.0;
            cout << "[MONITOR] Frames=" << frames << " bits=" << bits
                 << " avg delay(ms)=" << avg_delay_ms << "\n";
        } });

    for (int i = 0; i < n_clients; ++i)
    {
        clients.emplace_back(client_worker, i, server_ip, frames_per_client);
        this_thread::sleep_for(chrono::milliseconds(20));
    }

    for (auto &t : clients)
        t.join();
    stop_monitor = true;
    monitor.join();

    auto end_all = chrono::steady_clock::now();
    double total_time_s = chrono::duration<double>(end_all - start_all).count();

    long long final_bits = total_successful_bits.load();
    long long final_frames = total_successful_frames.load();
    long long final_delayus = total_delay_us.load();

    double throughput_bps = final_bits / total_time_s;
    double avg_delay_ms = final_frames ? (final_delayus / (double)final_frames / 1000.0) : 0.0;

    cout << "\n=== SIMULATION COMPLETE ===\n";
    cout << "Clients: " << n_clients << " Frames/client: " << frames_per_client << "\n";
    cout << "Throughput (Mbps): " << throughput_bps / 1e6 << "\n";
    cout << "Avg Forwarding Delay (ms): " << avg_delay_ms << "\n";
    return 0;
}
