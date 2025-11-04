#include "dns_server.h"

int main()
{
    DNSServer server(8053);
    server.start();
    return 0;
}
