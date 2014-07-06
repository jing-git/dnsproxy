# build dnsproxy executable when user executes "make"
CC=gcc
LDFLAGS=-lpthread -lm
CFLAGS=-std=gnu99 -Wall -g -DDEBUG
dnsproxy: dnsproxy.o dnsresolve.o utils.o jconf.o json.o dnscache.o
	$(CC) $(LDFLAGS) dnsproxy.o dnsresolve.o utils.o jconf.o json.o dnscache.o -o dnsproxy
dnsproxy.o: dnsproxy.c
	$(CC) $(CFLAGS) -c dnsproxy.c
dnsresolve.o: dnsresolve.c
	$(CC) $(CFLAGS) -c dnsresolve.c
utils.o: utils.c
	$(CC) $(CFLAGS) -c utils.c
jconf.o: jconf.c
	$(CC) $(CFLAGS) -c jconf.c
json.o: json.c
	$(CC) $(CFLAGS) -c json.c
dnscache.o: dnscache.c
	$(CC) $(CFLAGS) -c dnscache.c  
    
# remove object files and executable when user executes "make clean"
clean:
	rm *.o dnsproxy
