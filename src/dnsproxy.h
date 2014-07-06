#ifndef DNSPROXY_H_
#define DNSPROXY_H_

#include <netdb.h>
#include <stdio.h>
#include <sys/socket.h>

#include "jconf.h"

#define VERSION "0.1.0"

#define DEFAULT_SERVER_PORT "5300"
#define DEFAULT_CONFIG_PATH "/etc/config/dnsproxy.json"

enum sizeConstants {
  MAXSTRINGLENGTH = 256,
  MAX_DOMAIN_LEN = 30,
};

typedef struct _node_
{
    char domain[MAX_DOMAIN_LEN];
    char *dns_result;
    ssize_t dns_length;
    struct _node_  *next;

} linknode,*linklist;

linklist Query (linklist p,char* ipaddr);
linklist CreatEmptyLink ();

// Create, bind, a new UDP server socket
int SetupUDPServerSocket(const char *service);
// Handle new UDP client
void HandleUDPClient(struct sockaddr_storage clntSock, char *dnsRequest);
//insert dns cache to list
void InsertEmptyLink(linklist p, char *domain, char *dns_result, ssize_t dns_length);
//check cache
#ifdef DEBUG
void CheckList(linklist p);
#endif
//convert to network ip
uint32_t convert_to_net_ip(char *ipAddress);
//sort fake ip list
void sort_fake_ip(uint32_t *fake_dns_addr, int fake_addr_num);

extern char *servPort;
extern linklist cacheList;
extern int servSock;
extern char udp_dns_server[16];
extern char tcp_dns_server[16];
extern uint32_t fake_dns_addr[MAX_FAKE_ADDR_NUM];
extern int fake_addr_num;

#endif // PRACTICAL_H_
