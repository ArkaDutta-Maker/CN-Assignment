#ifndef DNS_SERVER_H
#define DNS_SERVER_H

#include <vector>
#include <string>
#include <thread>
#include <cstdint>
#include "dns_cache.h"
#include "dns_utils.h"
class DNSServer
{
private:
    int port;
    DNSCache cache;

    std::vector<uint8_t> readTCPQuery(int clientSock);
    void sendTCPResponse(int clientSock, const std::vector<uint8_t> &resp);

    std::vector<uint8_t> queryUpstreamUDP(const std::vector<uint8_t> &query,
                                          const std::string &server, int port);
    std::vector<uint8_t> queryUpstreamTCP(const std::vector<uint8_t> &query,
                                          const std::string &server, int port);
    std::vector<uint8_t> queryUpstream(const std::vector<uint8_t> &query,
                                       const std::string &server, int port);

    void handleClient(int clientSock);
    void handleUDP(int udpSock);

    void udpListener();

public:
    explicit DNSServer(int p);
    DNSCache *getCache();
    void start();
};

#endif // DNS_SERVER_H
