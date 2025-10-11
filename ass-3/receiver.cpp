#include "common.h"
#include <bits/stdc++.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <thread>
#include <mutex>
#include <vector>
#include <atomic>
using namespace std;

static constexpr int PORT = 9090;

mutex channel_mtx;
bool channel_busy_flag = false;
atomic<int> collision_count{0};    // ✅ Total collisions detected
atomic<int> active_clients{0};     // ✅ Track connected clients
atomic<bool> server_running{true}; // ✅ Controls monitor thread

void handle_client(int client_sock, int id)
{
    active_clients++;
    char buffer[2048];

    while (true)
    {
        memset(buffer, 0, sizeof(buffer));
        int n = recv(client_sock, buffer, sizeof(buffer), 0);
        if (n <= 0)
            break;

        bool collided = false;

        {
            lock_guard<mutex> lock(channel_mtx);
            if (channel_busy_flag)
            {
                cerr << "[Receiver] Collision detected for Client " << id << "\n";
                collision_count++; // ✅ Increment counter
                collided = true;
            }
            else
            {
                channel_busy_flag = true;
            }
        }

        if (collided)
        {
            // Drop frame (simulate collision)
            continue;
        }

        // Simulate processing delay
        this_thread::sleep_for(chrono::milliseconds(20));

        send(client_sock, "ACK", 3, 0);

        {
            lock_guard<mutex> lock(channel_mtx);
            channel_busy_flag = false;
        }
    }

    close(client_sock);
    cout << "Receiver: Client " << id << " disconnected\n";
    active_clients--;
}

int main()
{
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0)
    {
        cerr << "Socket creation failed\n";
        return 1;
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_fd, (sockaddr *)&addr, sizeof(addr)) < 0)
    {
        cerr << "Bind failed\n";
        return 1;
    }

    listen(server_fd, 10);
    cout << "Receiver listening on port " << PORT << "...\n";

    vector<thread> threads;
    int client_id = 0;

    // Monitoring thread to show live stats
    thread monitor_thread([]
                          {
        while (server_running)
        {
            this_thread::sleep_for(chrono::seconds(3));
            cout << "[Monitor] Active clients: " << active_clients.load()
                 << ", Collisions so far: " << collision_count.load() << "\n";
        } });

    // Accept clients until all disconnect
    auto start_time = chrono::steady_clock::now();
    while (true)
    {
        sockaddr_in caddr{};
        socklen_t clen = sizeof(caddr);
        int client_sock = accept(server_fd, (sockaddr *)&caddr, &clen);

        if (client_sock >= 0)
        {
            cout << "Client " << client_id << " connected.\n";
            threads.emplace_back(handle_client, client_sock, client_id++);
        }
        else
        {
            break;
        }

        // If some time has passed and no clients are active, stop
        if (client_id > 0 && active_clients.load() == 0)
        {
            this_thread::sleep_for(chrono::seconds(2));
            if (active_clients.load() == 0)
                break;
        }
    }

    server_running = false;
    if (monitor_thread.joinable())
        monitor_thread.join();

    for (auto &t : threads)
        if (t.joinable())
            t.join();

    close(server_fd);

    auto end_time = chrono::steady_clock::now();
    double total_time_s = chrono::duration<double>(end_time - start_time).count();

    cout << "\n=== SERVER SUMMARY ===\n";
    cout << "Total clients served: " << client_id << "\n";
    cout << "Total collisions detected: " << collision_count.load() << "\n";
    cout << "Total active time (s): " << total_time_s << "\n";
    cout << "Server shutting down gracefully.\n";

    return 0;
}
