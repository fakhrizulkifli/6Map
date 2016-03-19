/*
 * vim:sw=4 ts=4:et sta
 *
 *
 * Copyright (c) 2016, Fakhri Zulkifli <mohdfakhrizulkifli at gmail dot com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * * Neither the name of 6map nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <signal.h>
#include <unistd.h>
#include <execinfo.h>
#include <errno.h>
#include "6map.h"
#include "logger.h"
#include "neighbor.h"
#include "utils.h"
#include "icmp6.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/tcp.h>

#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <sys/ioctl.h>
#include <bits/ioctls.h>
#include <bits/socket.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>

#define TRACE_SIZE 256

const struct option opts[] =
{
    {"help", no_argument, 0, 'h'},
    {"interface", required_argument, 0, 'i'},
    {"destination", required_argument, 0, 'd'},
    {"source", optional_argument, 0, 's'},
    {"ping", no_argument, 0, 'p'},
    {"port", required_argument, 0, 'P'},
    {"router", no_argument, 0, 'r'},
    {"arp", no_argument, 0, 'a'},
    {"version", no_argument, 0, 'V'},
    {"verbose", no_argument, 0, 'v'},
    {NULL, 0, NULL, 0}
};

void
usage()
{
    printf("Usage: ./6map options\n");
    printf("OPTIONS:\n\t");
    printf("-h, --help\thelp\n\t");
    printf("-i, --iface\tinterface\n\t");
    printf("-t, --target\ttarget\n\t");
    printf("-p, --ping\tping-based port scan\n\t");
    printf("-r, --router\trouter scan\n\t");
    printf("-a, --arp\tARP-based scan\n\t");
    printf("-P, --port\tport\n\t");
    printf("-V, --version\tversion\n\t");
    printf("-v, --verbose\tverbose\n");
}

void
banner()
{
    printf("6map v%s -- IPv6 Mapper\n", VERSION);
    printf("Copyright (c) 2016 Fakhri Zulkifli\n");
    printf("<mohdfakhrizulkifli at gmail dot com>\n");
}

static void
segfault_handler(int sig)
{
    void *func[TRACE_SIZE];
    char **symb = NULL;
    int size, i;

    size = backtrace(func, TRACE_SIZE);
    symb = backtrace_symbols(func, size);

    for (i = 0; i < size; ++i)
    {
        fprintf(stderr, "[bt]: %s\n", symb[i]);
    }
    fflush(stderr);
    free(symb);
    exit(sig);
}

static void
sigint_handler(int sig)
{
    fprintf(stderr, "Ctrl-c detected!\n");
    fflush(stderr);
    exit(sig);
}

/*
 *int
 *recv_icmp(struct _scan scan)
 *{
 *}
 */

/*
 *int
 *recv_arp_reply(struct _idata idata)
 *{
 *}
 */

int
recv_neighbor_advert(struct _idata idata)
{
    int i;
    int sd;
    int ret;
    int len;
    u_int8_t neigh_addr, *pkt;
    struct _neighbor neigh;
    struct nd_neighbor_advert *na;
    struct msghdr msghdr;
    struct iovec iov[2];
    struct ifreq ifr;

    neigh.inpack = allocate_ustrmem(IP_MAXPACKET);

    memset(&iov, 0, sizeof(struct iovec));
    memset(&msghdr, 0, sizeof(struct msghdr));

    msghdr.msg_name = NULL;
    msghdr.msg_namelen = 0;
    iov[0].iov_base = (u_int8_t *) neigh.inpack;
    iov[0].iov_len = IP_MAXPACKET;
    msghdr.msg_iov = iov;
    msghdr.msg_iovlen = 1;

    msghdr.msg_control = allocate_ustrmem(IP_MAXPACKET);
    msghdr.msg_controllen = IP_MAXPACKET * sizeof(u_int8_t);

    if ((sd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)) < 0)
    {
        perror("RecvNeighAdvert.socket");
        exit(EXIT_FAILURE);
    }

    memcpy(&ifr.ifr_name, &idata.iface, sizeof(ifr.ifr_name));
    memcpy(&ifr.ifr_hwaddr.sa_data, &idata.src_mac, sizeof(ifr.ifr_hwaddr.sa_data));
    if (bind(sd, (struct sockaddr *) &ifr, sizeof(ifr)) != 0)
    {
        perror("RecvNeighAdvert.bind");
        exit(EXIT_FAILURE);
    }
    /*
     *if (setsockopt(sd, SOL_SOCKET, S0_BINDTODEVICE, (void *) &ifr, sizeof(struct ifreq)) < 0)
     *{
     *    perror("RecvNeighAdvert.SO_BINDTODEVICE");
     *    exit(EXIT_FAILURE);
     *}
     */

    // listening for incoming
    na = (struct nd_neighbor_advert *) neigh.inpack;
    while (na->nd_na_hdr.icmp6_type != ND_NEIGHBOR_ADVERT)
    {
        if ((len = recvmsg(sd, &msghdr, 0)) < 0)
        {
            perror("RecvNeighAdvert.recvmsg");
            return(EXIT_FAILURE);
        }
    }

    // data received
    LOG(2, "Got a response!");

    /* TODO: Recheck all memset/malloc sizeof() */
    /* TODO: Recheck all the LOG and what should be printed without -v */
    memcpy(&neigh_addr, &na->nd_na_target, sizeof(u_int8_t));
    if ((ret = validate_ip_addr(neigh_addr)) == 0)
    {
        LOG(1, "Neighbor Solicited address: %s\n", &na->nd_na_target);
        LOG(1, "Neighbor Solicited MAC address: ");

        pkt = (u_int8_t *) neigh.inpack;
        for (i = 2; i < 7; ++i)
        {
            LOG(1, "%02x:", pkt[sizeof(struct nd_neighbor_advert) + i]);
        }
        LOG(1, "%02x\n", pkt[sizeof(struct nd_neighbor_advert) + 7]);
    }

    close(sd);
    free_neighbor(neigh);
    free_idata(idata);
    return 0;
}

/*
 *int
 *recv_router_advert(struct _router route)
 *{
 *}
 */

/*
 * @brief get the ipv4 address via arp, then send icmp6, if reply get the address
 *int
 *send_arp(struct _idata idata)
 *{
 *}
 */

int
send_neighbor_solicit(struct _idata idata, struct _scan scan)
{
    int ret;
    int sd;
    struct _neighbor neigh;
    struct msghdr msghdr;
    struct _idata dat;

    memcpy(&dat, &idata, sizeof(struct _idata));
    msghdr = neighbor_solicit(neigh, idata, scan);

    if ((sd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)) < 0)
    {
        perror("SendNeighSolicit.socket");
        exit(EXIT_FAILURE);
    }

    /*
     * FIXME: Address family not supported
     */
    if ((sendmsg(sd, &msghdr, 0)) != -1)
    {
        perror("SendNeighSolicit.sendmsg");
        exit(EXIT_FAILURE);
    }

    if ((ret = recv_neighbor_advert(dat)) != 0)
    {
        perror("SendNeighAdvert.recv_neighbor_advert");
        exit(EXIT_FAILURE);
    }

    return 0;
}

/*
 *int
 *send_router_solicit(struct _router route)
 *{
 *
 *}
 */

/*
 *int
 *send_icmp(struct _scan scan, u_int8_t port)
 *{
 *}
 */

int
main(int argc, char **argv)
{
    int ret;
    int status;
    u_int8_t port;
    struct _idata dat, idata;
    struct _scan scan;
    struct sockaddr_in6 sa;

    signal(SIGINT, sigint_handler);
    signal(SIGSEGV, segfault_handler);
    memset(&idata, 0, sizeof(struct _idata));
    memset(&scan, 0, sizeof(struct _scan));

    if (argc < 2)
    {
        usage();
        exit(EXIT_FAILURE);
    }

    while ((ret = getopt_long(argc, argv, "hi:t:vVd:s:pP:ra", opts, NULL)) != -1)
    {
        switch (ret)
        {
            case 'h':
                usage(argv);
                exit(EXIT_FAILURE);

            case 'i':
                dat.iface = strdup(optarg);
                break;

            case 'd':
                if ((inet_pton(AF_INET6, optarg, &(sa.sin6_addr))) != 1)
                {
                    perror("inet_pton");
                    exit(EXIT_FAILURE);
                }
                scan.dst_ip = strdup(optarg);
                break;

            case 's':
                if ((inet_pton(AF_INET6, optarg, &(sa.sin6_addr))) != 1)
                {
                    perror("inet_pton");
                    exit(EXIT_SUCCESS);
                }
                scan.src_ip = strdup(optarg);
                break;

            case 'p':
                scan.ping_flag = 1;
                break;

            case 'P':
                port = optarg;
                break;

            case 'r':
                scan.router_flag = 1;
                break;

            case 'V':
                banner();
                exit(EXIT_SUCCESS);

            case 'v':
                LOG_add_level(1);
                break;
        }
    }

    idata  = init_interface(dat);
/*
 *    if ((scan.router_flag == 1) && (scan.ping_flag == 0) && (scan.arp_flag == 0))
 *    {
 *        send_router_solicit(idata, scan);
 *    }
 *
 *    if ((scan.router_flag == 0) && (scan.ping_flag == 1) && (scan.arp_flag == 0))
 *    {
 *        send_icmp(idata, scan);
 *    }
 *
 *    if ((scan.router_flag == 0) && (scan.ping_flag == 0) && (scan.arp_flag == 1))
 *    {
 *        send_arp(idata);
 *    }
 */

    if ((status = send_neighbor_solicit(idata, scan)) == 0)
    {
    }
    /*
     *for (;;)
     *    recv_neighbor_advert(idata, scan);
     */

    return EXIT_SUCCESS;
}
