#ifndef DNS_SERVER_H
#define DNS_SERVER_H

#include "dns_cache.h"
#include "dns_utils.h"
#include <vector>
#include <thread>
#include <mutex>

class DNSServer
{
    int port;
    DNSCache cache;

    std::vector<uint8_t> readTCPQuery(int clientSock);
    void sendTCPResponse(int clientSock, const std::vector<uint8_t> &resp);
    void handleClient(int clientSock);

public:
    DNSServer(int port);
    void start();
};

#endif
