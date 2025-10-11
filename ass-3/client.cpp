#include "common.h"
#include <bits/stdc++.h>
#include <thread>
#include <atomic>
#include <mutex>
#include <random>
#include <chrono>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
#include <fcntl.h>
using namespace std;

static constexpr int PORT = 9090;

// Global stats
atomic<long long> total_successful_bits{0};
atomic<long long> total_successful_frames{0};
atomic<long long> total_delay_us{0};
mutex stats_mtx;

// Parameters
double P_persistent = 0.5;
int slot_ms = 5;
int ack_timeout_ms = 200;
int max_BEB_k = 6;
double collisionProb = 0.1;

// Random generator
random_device rd;
mt19937 rng(rd());
uniform_real_distribution<double> prob_dist(0.0, 1.0);

// --- Helper: Non-blocking channel probe ---
bool channel_busy(int sockfd)
{
    fd_set rfds;
    struct timeval tv;
    FD_ZERO(&rfds);
    FD_SET(sockfd, &rfds);
    tv.tv_sec = 0;
    tv.tv_usec = 1000; // 1 ms check
    int ret = select(sockfd + 1, &rfds, nullptr, nullptr, &tv);
    return (ret > 0); // busy if data pending
}

// --- Client Thread Function ---
void client_worker(int id, string server_ip, int frames_per_client)
{
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
    {
        cerr << "Client " << id << " socket failed\n";
        return;
    }

    sockaddr_in serv_addr{};
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    inet_pton(AF_INET, server_ip.c_str(), &serv_addr.sin_addr);

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        cerr << "Client " << id << " connection failed\n";
        return;
    }

    cout << "Client " << id << " connected.\n";

    // Read data bits from msg.bits
    ifstream fin("msg.bits");
    string bits;
    getline(fin, bits);
    if (bits.empty())
        bits = "1011001010101110";
    fin.close();

    int frame_size = bits.size();
    vector<string> frames(frames_per_client, bits);

    for (int f = 0; f < frames_per_client; ++f)
    {
        int attempt = 0;
        auto start_tx = chrono::steady_clock::now();

        while (true)
        {
            // Channel sensing
            if (channel_busy(sock))
            {
                this_thread::sleep_for(chrono::milliseconds(slot_ms));
                continue;
            }

            // p-persistent transmit decision
            if (prob_dist(rng) > P_persistent)
            {
                this_thread::sleep_for(chrono::milliseconds(slot_ms));
                continue;
            }

            // Optional random collision injection
            bool local_collision = (prob_dist(rng) < collisionProb);

            // Send frame
            string frame = frames[f];
            send(sock, frame.c_str(), frame.size(), 0);

            if (local_collision)
            {
                cerr << "[Client " << id << "] Injected collision.\n";
                attempt++;
                int backoff_slots = rand() % (1 << min(attempt, max_BEB_k));
                this_thread::sleep_for(chrono::milliseconds(slot_ms * backoff_slots));
                continue;
            }

            // Wait for ACK
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(sock, &rfds);
            struct timeval tv;
            tv.tv_sec = ack_timeout_ms / 1000;
            tv.tv_usec = (ack_timeout_ms % 1000) * 1000;

            int ret = select(sock + 1, &rfds, nullptr, nullptr, &tv);
            if (ret > 0 && FD_ISSET(sock, &rfds))
            {
                char buffer[16];
                int n = recv(sock, buffer, sizeof(buffer), 0);
                if (n > 0 && strncmp(buffer, "ACK", 3) == 0)
                {
                    auto end_tx = chrono::steady_clock::now();
                    long long delay_us =
                        chrono::duration_cast<chrono::microseconds>(end_tx - start_tx).count();
                    total_delay_us += delay_us;
                    total_successful_frames++;
                    total_successful_bits += frame_size;
                    break;
                }
            }

            // Collision (timeout)
            attempt++;
            int backoff_slots = rand() % (1 << min(attempt, max_BEB_k));
            this_thread::sleep_for(chrono::milliseconds(slot_ms * backoff_slots));
        }
    }

    close(sock);
    cout << "Client " << id << " finished.\n";
}

// --- Main ---
int main()
{
    string server_ip = "127.0.0.1";
    int n_clients = 3, frames_per_client;

    cout << "Enter number of clients (threads): ";
    cin >> n_clients;
    cout << "Frames per client: ";
    cin >> frames_per_client;
    cout << "p (persistence, 0..1): ";
    cin >> P_persistent;
    cout << "slot time (ms): ";
    cin >> slot_ms;
    cout << "ACK timeout (ms): ";
    cin >> ack_timeout_ms;
    cout << "Max BEB exponent (k): ";
    cin >> max_BEB_k;
    cout << "collisionProb (sender-side optional, 0 for rely on receiver): ";
    cin >> collisionProb;

    vector<thread> clients;
    auto start_all = chrono::steady_clock::now();

    for (int i = 0; i < n_clients; ++i)
    {
        clients.emplace_back(client_worker, i, server_ip, frames_per_client);
        this_thread::sleep_for(chrono::milliseconds(20));
    }

    atomic<bool> stop_monitor{false};
    thread monitor([&]()
                   {
        while (!stop_monitor) {
            this_thread::sleep_for(chrono::seconds(3));
            long long bits = total_successful_bits.load();
            long long frames = total_successful_frames.load();
            long long delayus = total_delay_us.load();
            double avg_delay_ms = frames ? (delayus / (double)frames / 1000.0) : 0.0;
            cout << "[MON] Total success frames=" << frames
                 << ", bits=" << bits
                 << ", avg delay(ms)=" << avg_delay_ms << "\n";
        } });

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
    cout << "Clients: " << n_clients << ", Frames/client: " << frames_per_client << "\n";
    cout << "Throughput (bps): " << throughput_bps << "\n";
    cout << "Throughput (Mbps): " << throughput_bps / 1e6 << "\n";
    cout << "Average forwarding delay (ms): " << avg_delay_ms << "\n";
}
