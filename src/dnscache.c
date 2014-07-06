#include<stdio.h>
#include<fcntl.h>
#include<stdlib.h>
#include<string.h>
#include<stdbool.h>
#include<ctype.h>
#include<arpa/inet.h>

#include "dnsproxy.h"
#include "utils.h"

linklist CreatEmptyLink ( )      // creat an empty link;return the head dress of the link
{
	linklist h = (linklist)malloc(sizeof(linknode));
	h->next = NULL;
	return h;
}

void InsertEmptyLink(linklist p, char *domain, char *dns_result, ssize_t dns_length) // insert a node at the head of the link
{
    if(strlen(domain) > MAX_DOMAIN_LEN) return;
	linklist h = (linklist)malloc(sizeof(linknode));
	memset((void *)h, 0, sizeof(linknode));
	strncpy(h -> domain, domain, MAX_DOMAIN_LEN);
    h -> dns_result = (char*)malloc(dns_length);
    memcpy(h -> dns_result, dns_result, dns_length);
    h -> dns_length = dns_length;
    
    while (p->next) {
        if (strcmp(p->next->domain,domain) > 0) {
            h -> next = p-> next;
            p -> next = h;
            return;
        }
        p = p->next;
    }
    h -> next = p-> next;
    p -> next = h;
	
}

linklist Query(linklist p,char* domain) {
    if(strlen(domain) > MAX_DOMAIN_LEN) return NULL;
    while (p->next) {
        int str_cmp = strcmp(p->next->domain,domain);
        if (str_cmp == 0) {
            return p->next;
        }else if(str_cmp > 0){
            return NULL;
        }        
        p = p->next;
    }
    return NULL;
}

#ifdef DEBUG
void CheckList(linklist p) {
    while (p->next) {
        printf("the current dns cache list domain = %s\n",p->next->domain);
        p = p->next;
    }
}
#endif

/*
void Update(linklist p,int  ipType) {
    p -> ipType = ipType;
}
*/
static void swap(uint32_t *x,uint32_t *y){
    uint32_t temp;
    temp = *x;
    *x = *y;
    *y = temp;
}

void sort_fake_ip(uint32_t *fake_dns_addr, int fake_addr_num){
    int i,j;
    for(i=0;i<fake_addr_num-1;i++){
        for(j = i + 1;j < fake_addr_num; j++){
            if(fake_dns_addr[i] > fake_dns_addr[j]){
                swap(&fake_dns_addr[i],&fake_dns_addr[j]);    
            }
        }    
    }
}

uint32_t convert_to_net_ip(char *ipAddress)
{
    struct sockaddr_in sa;
    if(!inet_pton(AF_INET, ipAddress, &(sa.sin_addr))) {
        LOGE("invalid ipaddr=%s in fake ip list", ipAddress);
    }
    return sa.sin_addr.s_addr;
}
