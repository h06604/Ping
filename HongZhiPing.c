#include <math.h>
#include <time.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <assert.h>
#ifndef _WIN32
    #include <unistd.h>
    #include <signal.h>
    #include <netdb.h>
    #include <netinet/ip_icmp.h>
    #include <netinet/ip.h>
    #include <netinet/in.h>
    #include <netinet/tcp.h>
    #include <arpa/inet.h>
    #include <sys/ioctl.h>
    #include <sys/time.h>
    #include <sys/socket.h>
    #include <pthread.h>
    #include <sysexits.h>
    #include<features.h>
    #include<linux/if_packet.h>
    #include<linux/if_ether.h>
    #include<sys/ioctl.h>
    #include<net/if.h>
    #define SOCKET_T int
    #define SOCKLEN_T socklen_t
    #define MY_EX_USAGE EX_USAGE
    #define INVALID_SOCKET (-1)
#endif

#include <event2/event.h>



#define MSG_SIZE 1500
#define pkt_number 1000
char* serverString = NULL;
struct event_base* base;               /* main base */
struct sockaddr_in server;
struct timeval timeval1;
struct event* sendEvent;
struct event* recvEvent;
struct event *sig_event;
int pingCount = 0;
int msgCount = 0;
double firstsend = 0.0;
double sendtime = 0.0;    
int time1 = -1;
bool keepalive = false;
int ttl   = 0;                 

int   myoptind;
char* myoptarg;


static int GetOpt(int argc, char** argv, const char* optstring)
{
    static char* next = NULL;

    char  c;
    char* cp;

    if (myoptind == 0)
        next = NULL;   /* we're starting new/over */

    if (next == NULL || *next == '\0') {
        if (myoptind == 0)
            myoptind++;

        if (myoptind >= argc || argv[myoptind][0] != '-' ||
                                argv[myoptind][1] == '\0') {
            myoptarg = NULL;
            if (myoptind < argc)
                myoptarg = argv[myoptind];

            return -1;
        }

        if (strcmp(argv[myoptind], "--") == 0) {
            myoptind++;
            myoptarg = NULL;

            if (myoptind < argc)
                myoptarg = argv[myoptind];

            return -1;
        }

        next = argv[myoptind];
        next++;                  /* skip - */
        myoptind++;
    }

    c  = *next++;
    /* The C++ strchr can return a different value */
    cp = (char*)strchr(optstring, c);

    if (cp == NULL || c == ':')
        return '?';

    cp++;

    if (*cp == ':') {
        if (*next != '\0') {
            myoptarg = next;
            next     = NULL;
        }
        else if (myoptind < argc) {
            myoptarg = argv[myoptind];
            myoptind++;
        }
        else
            return '?';
    }

    return c;
}

double get_ms (void)
{
    double            ms; // Milliseconds
    time_t          s;
    struct timeval spec;
    double combine;
    //clock_gettime(CLOCK_REALTIME, &spec);
    gettimeofday(&spec,NULL);
    //printf("%ld\n",spec.tv_usec);
    s  = spec.tv_sec;
    ms = (double)spec.tv_usec / 1.0e6; // Convert nanoseconds to milliseconds

    combine = (double)s + (double)ms;

    //printf("%f\n", combine);
    return combine;
}


static void newRecv(evutil_socket_t fd, short which, void* arg)
{

    char msg[MSG_SIZE];
    int  msgLen;
    double recvtime = 0.0;
    struct iphdr *recv_iphdr;
    struct icmphdr *recv_icmphdr;

    msgLen = recv(fd, msg, MSG_SIZE, 0);
    if(msgLen > 0){
        recv_iphdr = (struct iphdr *)msg;
        recv_icmphdr = (struct icmphdr *)(msg + (recv_iphdr->ihl << 2));
        if(recv_icmphdr->type == ICMP_ECHOREPLY){
            recvtime = get_ms();
            if(msgCount == 0){
                printf("%d bytes from %s time =%fms TTL=%d\n", msgLen, serverString,(recvtime - firstsend) * 1000, recv_iphdr->ttl);
            }
            else{
                printf("%d bytes from %s time =%fms TTL=%d\n", msgLen, serverString,(recvtime - sendtime) * 1000, recv_iphdr->ttl);
            }
            msgCount++;
        }
    }


    
}

static void newPing(evutil_socket_t fd, short which, void* arg){

    int ret = 0;

    static struct icmphdr icmphdr;

    if(msgCount == 0){
        memset(&icmphdr, 0, sizeof(icmphdr));
    }
    
    if(time1 > 0){
        setup_icmphdr(ICMP_ECHO, 0, 0, msgCount, &icmphdr);
        ret = sendto(fd, (char *)&icmphdr, sizeof(icmphdr), 0, (struct sockaddr *)&server, sizeof(server));
        pingCount++;
        time1--;
        sendtime = get_ms();
        if (ret < 0) {
            perror("send failed");
            exit(EXIT_FAILURE);
        }
        timeval1.tv_sec = 1;
        timeval1.tv_usec = 0;
        event_add(sendEvent, &timeval1);
        if (keepalive == true){
            time1++;
        }
    }
    else{
        handler(SIGINT,sig_event,NULL);
    }
    if(pingCount - msgCount >= 4){
        handler(SIGINT,sig_event,NULL);
    }


}

void handler(int signo, short events, void* arg) {
        double lossrate = 0.0;
        lossrate = 1.0 - (double)msgCount/(double)pingCount;
        printf("\n-----%s-----\n%d packets transmitted, %d received, %.1f%% packet loss\n",serverString,pingCount,msgCount,lossrate*100);
        //printf("rtt min\\arg\\max\n");
        exit(EXIT_SUCCESS);
}


static void Usage(void)
{
    printf("HongZhiPing \n");
    printf("-h                  Help, print this usage\n");
    printf("-t <times>          default 4\n");
    printf("-s <address>        address in dotted decimal\n");
    printf("-d                  keep alive\n");
    printf("-y <num>            ttl, default 64\n");
}

u_int16_t checksum(unsigned short *buf, int size)
{
    unsigned long sum = 0;
    while (size > 1) {
        sum += *buf;
        buf++;
        size -= 2;
    }
    if (size == 1)
        sum += *(unsigned char *)buf;
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    return ~sum;
}

void setup_icmphdr(u_int8_t type, u_int8_t code, u_int16_t id, u_int16_t seq, struct icmphdr *icmphdr)
{
    icmphdr->type = type;
    icmphdr->code = code;
    icmphdr->checksum = 0;
    icmphdr->un.echo.id = id;
    icmphdr->un.echo.sequence = seq;
    icmphdr->checksum = checksum((unsigned short *)icmphdr, sizeof(struct icmphdr));
}

int main(int argc, char** argv)
{
    SOCKET_T sockfd;
    int ret,ch = 1;
    struct icmphdr icmphdr;

    while ( (ch = GetOpt(argc, argv, "hdt:s:y:")) != -1) {
        switch (ch) {
            case 'h' :
                Usage();
                exit(EXIT_SUCCESS);
                break;

            case 't' :
                time1 = atoi(myoptarg);
                break;

            case 'd' :
                keepalive = true;
                break;

            case 'y' :
                ttl = atoi(myoptarg);
                break;

            case 's' :
                serverString = myoptarg;
                break;

            default:
                Usage();
                exit(MY_EX_USAGE);
                break;
        }
    }

    if (time1 == -1 && keepalive == false) {
        time1 = 4;
    }
    else if (keepalive == true){
        time1 = 99;
    }

    if(ttl == -1){
        ttl = 64;
    }

    if (serverString == NULL) {
        printf("need to set destination address\n");
        Usage();
        exit(MY_EX_USAGE);
    }
    
    sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);

    if (sockfd < 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));

    memset(&server, 0, sizeof(server));
    server.sin_family = PF_INET;
    server.sin_addr.s_addr = inet_addr(serverString);
    if(inet_addr(serverString) == -1){
        printf("invalid address\n");
        Usage();
        exit(MY_EX_USAGE);
    }

    memset(&icmphdr, 0, sizeof(icmphdr));
    setup_icmphdr(ICMP_ECHO, 0, 0, 0, &icmphdr);

    base = event_base_new();
    if (base == NULL) {
        perror("event_base_new failed");
        exit(EXIT_FAILURE);
    }


    printf("Ping %s\n",serverString);
    time1--;
    pingCount++;
    firstsend = get_ms();
    ret = sendto(sockfd, (char *)&icmphdr, sizeof(icmphdr), 0, (struct sockaddr *)&server, sizeof(server));
    if (ret < 0) {
        perror("send failed");
        exit(EXIT_FAILURE);
    }

    sendEvent = event_new(base, sockfd, EV_TIMEOUT, newPing, NULL);
    if (sendEvent == NULL) {
        perror("event_new failed for sendEvent");
        exit(EXIT_FAILURE);
    }

    timeval1.tv_sec = 1;
    timeval1.tv_usec = 0;
    event_add(sendEvent, &timeval1);

    recvEvent = event_new(base, sockfd, EV_READ|EV_PERSIST, newRecv, NULL);
    if (recvEvent == NULL) {
        perror("event_new failed for recvEvent");
        exit(EXIT_FAILURE);
    }

    event_add(recvEvent, NULL);

    int signo = SIGINT;
    sig_event = evsignal_new(base, signo, handler, NULL);
    evsignal_add(sig_event, NULL);

    event_base_dispatch(base);

    printf("done with dispatching\n");

    return 0;
}
