#ifndef _JCONF_H
#define _JCONF_H

#define MAX_FAKE_ADDR_NUM 64
#define MAX_CONF_SIZE 16 * 1024

typedef struct
{
    int  fake_addr_num;
    char *udp_dns_server;
    char *tcp_dns_server;
    char *fake_dns_addr[MAX_FAKE_ADDR_NUM];
} jconf_t;


jconf_t *read_jconf(const char* file);

#endif // _JCONF_H
