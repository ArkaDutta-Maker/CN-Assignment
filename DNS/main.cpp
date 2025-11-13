#include "dns_server.h"
#include "dns_cache_ui.h"
#include <thread>
#include <iostream>

int main()
{
    DNSServer server(8053);
    std::cout << "\033c";

    std::thread uiThread([&]()
                         { runCacheUI(server.getCache()); });

    uiThread.detach();
    server.start();

    return 0;
}
