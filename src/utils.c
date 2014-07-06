#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/stat.h>

#include "utils.h"
#include "dnsproxy.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#define INT_DIGITS 19		/* enough for 64 bit integer */


#ifndef __MINGW32__
void ERROR(const char *s)
{
    char *msg = strerror(errno);
    LOGE("%s: %s", s, msg);

}
#endif

#ifdef __MINGW32__
char *ss_itoa(int i)
#else
char *itoa(int i)
#endif
{
    /* Room for INT_DIGITS digits, - and '\0' */
    static char buf[INT_DIGITS + 2];
    char *p = buf + INT_DIGITS + 1;	/* points to terminating '\0' */
    if (i >= 0)
    {
        do
        {
            *--p = '0' + (i % 10);
            i /= 10;
        }
        while (i != 0);
        return p;
    }
    else  			/* i < 0 */
    {
        do
        {
            *--p = '0' - (i % 10);
            i /= 10;
        }
        while (i != 0);
        *--p = '-';
    }
    return p;
}

char *ss_strndup(const char *s, size_t n)
{
    size_t len = strlen(s);
    char *ret;

    if (len <= n) return strdup(s);

    ret = malloc(n + 1);
    strncpy(ret, s, n);
    ret[n] = '\0';
    return ret;
}

void FATAL(const char *msg)
{
    LOGE("%s", msg);
    exit(-1);
}

#ifdef DEBUG
void print_buffer(char *buffer, int numBytesRcvd){
    int i = 0;
    while(i < numBytesRcvd){
        printf("\\%02X",buffer[i]);
        i++;
    }
    fputc('\n', stdout);
}
#endif

void usage()
{
    printf("\n");
    printf("dnsproxy used to protect form dns poison --version %s\n\n", VERSION);
    printf("  maintained by Scola <shaozheng.wu@gmail.com>\n\n");
    printf("  usage:\n\n");
    printf("    This program is mainly used for openwrt router,but it still works on linux\n");
    printf("    Just run [./dnsproxy] after build and use dig to check\n");
    printf("    [dig @127.0.0.1 -p 5300 twitter.com]\n");
    printf("    On openwrt router you can use iptables to redirect dns to dnsproxy\n");
    printf("    [iptables -t nat -I PREROUTING -p udp  --dport 53 -j REDIRECT --to-ports 5300]\n");
    printf("\n");
    printf("    [-p <servPort>]         server port,the default value is 5300\n");
    printf("    [-c <config path>]      dnsproxy.json path,default /etc/config/dnsproxy.json\n");
    printf("    [-u <udp dns server>]   udp dns server,default 114.114.114.114\n");    
    printf("    [-t <tcp dns server>]   tcp dns server,default 8.8.8.8\n");
    printf("    [-h <help>]             get the usage of the dnsproxy\n");
    printf("\n");
}

void demonize(const char* path)
{
#ifndef __MINGW32__
    /* Our process ID and Session ID */
    pid_t pid, sid;

    /* Fork off the parent process */
    pid = fork();
    if (pid < 0)
    {
        exit(EXIT_FAILURE);
    }

    /* If we got a good PID, then
       we can exit the parent process. */
    if (pid > 0)
    {
        FILE *file = fopen(path, "w");
        if (file == NULL) FATAL("Invalid pid file\n");

        fprintf(file, "%d", pid);
        fclose(file);
        exit(EXIT_SUCCESS);
    }

    /* Change the file mode mask */
    umask(0);

    /* Open any logs here */

    /* Create a new SID for the child process */
    sid = setsid();
    if (sid < 0)
    {
        /* Log the failure */
        exit(EXIT_FAILURE);
    }

    /* Change the current working directory */
    if ((chdir("/")) < 0)
    {
        /* Log the failure */
        exit(EXIT_FAILURE);
    }

    /* Close out the standard file descriptors */
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
#endif
}

