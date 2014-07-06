#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>

#include "dnsproxy.h"
#include "utils.h"
#include "jconf.h"

char *servPort = NULL;
linklist cacheList = NULL;
int servSock = -1;
char udp_dns_server[16];
char tcp_dns_server[16];
uint32_t fake_dns_addr[MAX_FAKE_ADDR_NUM];
int fake_addr_num = 0;

void *ThreadMain(void *arg); // Main program of a thread

// Structure of arguments to pass to client thread
struct ThreadArgs {
    struct sockaddr_storage clntSock; // Socket descriptor for client
    char *dnsRequest;
};

static void create_thread(void *thread_func,void *threadArgs) {
    pthread_t threadID;
    int returnValue = pthread_create(&threadID, NULL, thread_func, threadArgs);
    if (returnValue != 0)
        FATAL("pthread_create() failed");
}

int main(int argc, char *argv[]) {
    char c;
    char *conf_path = DEFAULT_CONFIG_PATH;
    char *udp_server = NULL;
    char *tcp_server = NULL;

    servPort = DEFAULT_SERVER_PORT;

    opterr = 0;

    while ((c = getopt (argc, argv, "p:c:t:u:h")) != -1) {
        switch (c)
        {
            case 'p':
                servPort = optarg;
                break;
            case 'c':
                conf_path = optarg;
                break;
            case 'u':
                udp_server = optarg;   //it's just used for test oauth
                break;
            case 't':
                tcp_server = optarg;     //it's just used to test the twitter username display on the webpage
                break;
            case 'h':
                usage();
                exit(EXIT_SUCCESS);
                break;
            default:
                break;
        }
    }

    if (opterr) {
        usage();
        exit(EXIT_FAILURE);
    }
    
    if (conf_path != NULL)
    {   
        int i;
        jconf_t *conf = NULL;
        conf = read_jconf(conf_path);
        if (udp_server == NULL) udp_server = conf->udp_dns_server;
        if (tcp_server == NULL) tcp_server = conf->tcp_dns_server;
        fake_addr_num = conf->fake_addr_num;
        if (udp_server == NULL ||
            tcp_server == NULL || fake_addr_num == 0) {
            usage();
            exit(EXIT_FAILURE);
        }
        for (i = 0; i < fake_addr_num; i++)
        {
            fake_dns_addr[i] = convert_to_net_ip(conf->fake_dns_addr[i]);
#ifdef DEBUG            
            printf("net ip=%0X\n", fake_dns_addr[i]);
#endif             
        }
        sort_fake_ip(fake_dns_addr, fake_addr_num);
#ifdef DEBUG
        LOGD("sorted fake ip list");
        for (i = 0; i < fake_addr_num; i++)
        {            
            printf("net ip=%0X\n", fake_dns_addr[i]);
        }
#endif      
    }
    
    strncpy(udp_dns_server, udp_server, 16);
    strncpy(tcp_dns_server, tcp_server, 16);
    LOGD("udp_dns_server=%s   tcp_dns_server=%s\n", udp_dns_server, tcp_dns_server);
    
    //we need to create a thread to scan arp list and block some ip.
    cacheList = CreatEmptyLink();
    //create_thread(ScanArpList,NULL);
    LOGD("server listening at port %s...\n",servPort);

    servSock = SetupUDPServerSocket(servPort);
    if (servSock < 0)
        FATAL("unable to establish");
    for (;;) { // Run forever
        struct sockaddr_storage clntAddr; // Client address
        // Set Length of client address structure (in-out parameter)
        socklen_t clntAddrLen = sizeof(clntAddr);

        // Block until receive message from a client
        char buffer[MAXSTRINGLENGTH]; // I/O buffer
        // Size of received message
        ssize_t numBytesRcvd = recvfrom(servSock, buffer, MAXSTRINGLENGTH, 0,
            (struct sockaddr *) &clntAddr, &clntAddrLen);
        if (numBytesRcvd < 0)
            ERROR("recvfrom() failed");
#ifdef DEBUG        
        LOGD("get dns request for local");      
        print_buffer(buffer,numBytesRcvd);
#endif
        // Create separate memory for client argument
        struct ThreadArgs *threadArgs = (struct ThreadArgs *) malloc(
                sizeof(struct ThreadArgs));
        if (threadArgs == NULL)
            FATAL("malloc() failed");
        threadArgs->clntSock = clntAddr;
        threadArgs->dnsRequest = buffer;

        // Create client thread
        create_thread(ThreadMain,(void *)threadArgs);
    }
    // NOT REACHED
}

void *ThreadMain(void *threadArgs) {
    // Guarantees that thread resources are deallocated upon return
    pthread_detach(pthread_self());

    // Extract socket file descriptor from argument
    struct sockaddr_storage clntSock = ((struct ThreadArgs *) threadArgs)->clntSock;
    char *dnsRequest = ((struct ThreadArgs *) threadArgs)->dnsRequest;
    free(threadArgs); // Deallocate memory for argument

    HandleUDPClient(clntSock, dnsRequest);

    return (NULL);
}

