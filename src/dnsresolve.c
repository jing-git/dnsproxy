#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>

#include "dnsproxy.h"
#include "jconf.h"
#include "utils.h"

static bool is_little_endian()
{
    union w
    {
       int a;
       char b;
                  
    } c;
    c.a = 1;
    return(c.b == 1);
}

int SetupUDPServerSocket(const char *service) {
    // Construct the server address structure
    struct addrinfo addrCriteria;                                     // Criteria for address match
    memset(&addrCriteria, 0, sizeof(addrCriteria)); // Zero out structure
    addrCriteria.ai_family = AF_INET;                         // v4 address family
    addrCriteria.ai_flags = AI_PASSIVE;                         // Accept on any address/port
    addrCriteria.ai_socktype = SOCK_DGRAM;                 // Only dgram sockets
    addrCriteria.ai_protocol = IPPROTO_UDP;                 // Only UDP protocol

    struct addrinfo *servAddr; // List of server addresses
    int rtnVal = getaddrinfo(NULL, service, &addrCriteria, &servAddr);
    if (rtnVal != 0)
        ERROR("getaddrinfo() failed");

    int servSock = -1;
    for (struct addrinfo *addr = servAddr; addr != NULL; addr = addr->ai_next) {
        // Create a UDP socket
        servSock = socket(addr->ai_family, addr->ai_socktype,
                addr->ai_protocol);
        if (servSock < 0)
            continue;             // Socket creation failed; try next address
            
        int opt = 1;
        setsockopt(servSock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        // Bind to the local address and set socket to listen
        if ((bind(servSock, addr->ai_addr, addr->ai_addrlen) == 0)) {
            // Print local address of socket
            struct sockaddr_storage localAddr;
            socklen_t addrSize = sizeof(localAddr);
            //char addrBuffer[INET6_ADDRSTRLEN];
            if (getsockname(servSock, (struct sockaddr *) &localAddr, &addrSize) < 0)
                ERROR("getsockname() failed");
                
            break;             // Bind successful
        }

        close(servSock);    // Close and try again
        servSock = -1;
    }

    // Free address list allocated by getaddrinfo()
    freeaddrinfo(servAddr);

    return servSock;
}

int SetupTCPClientSocket(const char *host, const char *service) {
  // Tell the system what kind(s) of address info we want
  struct addrinfo addrCriteria;                   // Criteria for address match
  memset(&addrCriteria, 0, sizeof(addrCriteria)); // Zero out structure
  addrCriteria.ai_family = AF_INET;             // v4 only
  addrCriteria.ai_socktype = SOCK_STREAM;         // Only streaming sockets
  addrCriteria.ai_protocol = IPPROTO_TCP;         // Only TCP protocol

  // Get address(es)
  struct addrinfo *servAddr; // Holder for returned list of server addrs
  int rtnVal = getaddrinfo(host, service, &addrCriteria, &servAddr);
  if (rtnVal != 0)
    ERROR("getaddrinfo() failed");

  int sock = -1;
  for (struct addrinfo *addr = servAddr; addr != NULL; addr = addr->ai_next) {
    // Create a reliable, stream socket using TCP
    sock = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
    if (sock < 0)
      continue;  // Socket creation failed; try next address

    // Establish the connection to the echo server
    if (connect(sock, addr->ai_addr, addr->ai_addrlen) == 0)
      break;     // Socket connection succeeded; break and return socket

    close(sock); // Socket connection failed; try next address
    sock = -1;
  }

  freeaddrinfo(servAddr); // Free addrinfo allocated in getaddrinfo()
  return sock;
}

static void convert_domain(char *host, char *domain){
    int i = 1;
    int j = 0;
    while(*(host + i)){
        if(*(host + i) < 30) {
            domain[j] = '.';
        }else {
            domain[j] = *(host + i);
        }        
        j++;
        i++;
    }
}

static bool is_bad_reply(char *buffer){
    uint32_t net_ip;
    if(is_little_endian()){
        net_ip = (buffer[0] & 0xFF) + ((buffer[1] & 0xFF) << 8) + ((buffer[2] & 0xFF) << 16) + ((buffer[3] & 0xFF) << 24);
    }else {
        net_ip = (buffer[3] & 0xFF) + ((buffer[2] & 0xFF) << 8) + ((buffer[1] & 0xFF) << 16) + ((buffer[0] & 0xFF) << 24);
    }
    int i = 0;
    while(i < fake_addr_num) {
        if(net_ip == fake_dns_addr[i]) {
            return true;
        }else if(net_ip < fake_dns_addr[i]){
            return false;
        }
        i++;
    }
    return false;
}

static bool parser_dns_response(char *buffer, ssize_t numBytesRcvd){
    if(numBytesRcvd < 32) {
        LOGE("return bad dns packet");
        return false;
    }
    int i = 16;
    while(i < numBytesRcvd - 15){        
        if(buffer[i + 2] == 0 && buffer[i + 3] == 1 && buffer[i + 4] == 0 && buffer[i + 5] == 1 ){
#ifdef DEBUG
            LOGD("get dns result");
            print_buffer(buffer + i + 12, 4);
#endif            
            if(is_bad_reply(buffer + i + 12)){
                return false;
            }
        }       
        i++;
    }
    return true;
    
}

static void send_dns_to_local(struct sockaddr_storage clntSock, char *buffer, ssize_t numBytes){
    ssize_t numBytesSent = sendto(servSock, buffer, numBytes, 0,
        (struct sockaddr *) &clntSock, sizeof(clntSock));
    if (numBytesSent < 0)
      ERROR("sendto() failed)");
    
}

static void set_timeout(int sock){
    struct timeval timeout;
    timeout.tv_sec = 6;
    timeout.tv_usec = 0;
    
    if (setsockopt (sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout,
                                   sizeof(timeout)) < 0)
        ERROR("setsockopt failed");
}

static void remote_resolve(struct sockaddr_storage clntSock, char *dnsRequest, char *host){
    char *servPort = "53";
    char pre_data[10] = {1, 0, 0, 1, 0, 0, 0, 0, 0, 0};
    char end_data[5] = {0, 0, 1, 0, 1};
    char remote_request[MAXSTRINGLENGTH]= {0};
    srand(time(NULL));
    remote_request[0] = dnsRequest[0];
    remote_request[1] = dnsRequest[1];
    memcpy(remote_request + 2, pre_data, 10);
    int i = 0;
    while(*(host + i)){
        remote_request[12 + i] = *(host + i);
        i++;
    }
    memcpy(remote_request + 12 + i, end_data, 5);
#ifdef DEBUG    
    LOGD("send to remote dns request");
    print_buffer(remote_request, 17 + i);
#endif
    char domain[MAXSTRINGLENGTH] = {0};
    convert_domain(host, domain);
    
    LOGD("resolve domain=%s by udp dns server=%s", domain, udp_dns_server);
    
    // Tell the system what kind(s) of address info we want
    struct addrinfo addrCriteria;                   // Criteria for address match
    memset(&addrCriteria, 0, sizeof(addrCriteria)); // Zero out structure
    addrCriteria.ai_family = AF_INET;             // Any address family
    // For the following fields, a zero value means "don't care"
    addrCriteria.ai_socktype = SOCK_DGRAM;          // Only datagram sockets
    addrCriteria.ai_protocol = IPPROTO_UDP;         // Only UDP protocol

    // Get address(es)
    struct addrinfo *servAddr; // List of server addresses
    int rtnVal = getaddrinfo(udp_dns_server, servPort, &addrCriteria, &servAddr);
    if (rtnVal != 0)
        ERROR("getaddrinfo() failed");

    // Create a datagram/UDP socket
    int sock = socket(servAddr->ai_family, servAddr->ai_socktype,
      servAddr->ai_protocol); // Socket descriptor for client
    if (sock < 0)
        ERROR("socket() failed");

    // Send the string to the server
    ssize_t numBytes = sendto(sock, remote_request, 17 + i, 0,
      servAddr->ai_addr, servAddr->ai_addrlen);
    if (numBytes < 0)
        ERROR("sendto() failed");

    freeaddrinfo(servAddr); // Free addrinfo allocated in getaddrinfo()
    
    struct sockaddr_storage fromAddr; // Source address of server
    // Set length of from address structure (in-out parameter)
    socklen_t fromAddrLen = sizeof(fromAddr);
    char buffer[MAXSTRINGLENGTH]; // I/O buffer

    set_timeout(sock);
    numBytes = recvfrom(sock, buffer, MAXSTRINGLENGTH, 0,
            (struct sockaddr *) &fromAddr, &fromAddrLen);
    if (numBytes <= 0)
        ERROR("recvfrom() failed");
#ifdef DEBUG        
    LOGD("get dns response");   
    print_buffer(buffer, numBytes);
#endif    
    close(sock);
    
    if(parser_dns_response(buffer, numBytes)){
        buffer[0] = dnsRequest[0];
        buffer[1] = dnsRequest[1];
        send_dns_to_local(clntSock, buffer, numBytes);
        InsertEmptyLink(cacheList, host, buffer, numBytes);
#ifdef DEBUG        
        CheckList(cacheList);
#endif        
    } else{
        LOGE("resolve domain=%s return poison dns result", domain);
        LOGD("switch to tcp mode server=%s", tcp_dns_server);
        // Create a connected TCP socket
        int tcp_sock = SetupTCPClientSocket(tcp_dns_server, servPort);
        if (tcp_sock < 0)
            ERROR("SetupTCPClientSocket() failed");
            
        int j = 17 + i + 1;    
        while(j > 1) {
            remote_request[j] = remote_request[j - 2];
            j--;
        }
        remote_request[1] = 17 + i;
        remote_request[0] = 0;
#ifdef DEBUG        
        LOGD("send to remote tcp dns request");
        print_buffer(remote_request, 17 + i + 2);
#endif        
        // Send the string to the server
        ssize_t numBytes = send(tcp_sock, remote_request, 17 + i + 2, 0);
        if (numBytes < 0)
            ERROR("send() failed");
        
        set_timeout(tcp_sock);
        //char tcp_buffer[MAXSTRINGLENGTH]; // I/O buffer    
        numBytes = recv(tcp_sock, buffer, MAXSTRINGLENGTH, 0);
        if (numBytes < 0)
            ERROR("recv() failed");
        else if (numBytes == 0)
            ERROR("connection closed prematurely");
#ifdef DEBUG
        LOGD("recv tcp dns result");
        print_buffer(buffer, numBytes);
#endif
        if((buffer[1] & 0xFF) != numBytes - 2) {
            ERROR("return bad tcp packet");
        }else if(parser_dns_response(buffer + 2, numBytes - 2)) {
            buffer[2] = dnsRequest[0];
            buffer[3] = dnsRequest[1];
            send_dns_to_local(clntSock, buffer + 2, numBytes - 2);
            InsertEmptyLink(cacheList, host, buffer + 2, numBytes - 2);
#ifdef DEBUG
            CheckList(cacheList);
#endif            
        }
        close(tcp_sock);    
    }    
}

void HandleUDPClient(struct sockaddr_storage clntSock, char *dnsRequest){
    char domain[MAXSTRINGLENGTH] = {0};
    strcpy(domain, dnsRequest + 12);
    linklist cache = Query(cacheList, domain);
    if(cache != NULL) {
        *(cache -> dns_result) = dnsRequest[0];
        *(cache -> dns_result + 1) = dnsRequest[1];
        send_dns_to_local(clntSock, cache -> dns_result, cache -> dns_length);
    }else {
        remote_resolve(clntSock, dnsRequest, domain);
    }
}
