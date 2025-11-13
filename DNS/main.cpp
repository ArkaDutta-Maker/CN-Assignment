#include "dns_server.h"
#include "dns_cache_ui.h"
#include <thread>

int main()
{
    DNSServer server(8053);
    auto cache = server.getCache();

    std::thread uiThread(runCacheUI, cache);

    server.start();

    uiThread.join();
    return 0;
}
