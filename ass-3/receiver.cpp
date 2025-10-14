#include <bits/stdc++.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <thread>
#include <mutex>
#include <vector>
using namespace std;

static constexpr int PORT = 9090;
mutex channel_mtx;
bool channel_busy_flag = false;
int total_collisions = 0;

void handle_client(int client_sock, int id)
{
    char buffer[2048];
    while (true)
    {
        memset(buffer, 0, sizeof(buffer));
        int n = recv(client_sock, buffer, sizeof(buffer), 0);
        if (n <= 0)
            break;

        {
            lock_guard<mutex> lock(channel_mtx);
            if (channel_busy_flag)
            {
                cerr << "[Receiver] Collision detected for Client " << id << "\n";
                total_collisions++;
                continue; // drop frame
            }
            channel_busy_flag = true;
        }

        
        send(client_sock, "ACK", 3, 0);

        {
            lock_guard<mutex> lock(channel_mtx);
            channel_busy_flag = false;
        }
    }

    close(client_sock);
    cout << "Receiver: Client " << id << " disconnected\n";
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

    thread stats_printer([&]()
                         {
        while (true) {
            this_thread::sleep_for(chrono::seconds(5));
            cout << "[STATS] Total Collisions detected so far: " << total_collisions << "\n";
        } });

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
    }

    for (auto &t : threads)
        t.join();
    stats_printer.join();
    close(server_fd);
}
