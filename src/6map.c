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

#include <arpa/inet.h>
#include <netdb.h>
#include <net/if.h>
#include <net/ethernet.h>
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
#include "6map.h"
#include "logger.h"
#include "neighbor.h"
#include "arp.h"
#include "utils.h"
#include "icmp6.h"


#define TRACE_SIZE 256

const struct option opts[] =
{
    {"help", no_argument, 0, 'h'},
    {"interface", required_argument, 0, 'i'},
    {"ping", no_argument, 0, 'p'},
    {"target", required_argument, 0, 't'},
    {"mac", required_argument, 0, 'm'},
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
    printf("-r, --router\trouter-based scan\n\t");
    printf("-a, --arp\tARP-based scan\n\t");
    printf("-m, --mac\ttarget MAC address\n\t");
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

int
recv_arp_reply()
{
    int i;
    int sd;
    int ret;
    u_int8_t *ether_frame;
    struct _arp *arp_hdr;

    ether_frame = allocate_ustrmem(IP_MAXPACKET);
    memset(&arp_hdr, 0, sizeof(arp_hdr));

    if ((sd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
    {
        perror("RecvARP.socket");
        exit(EXIT_FAILURE);
    }

    arp_hdr = (struct _arp *) (ether_frame + 6 + 6 + 2);

    while ((((ether_frame[12] << 8) + ether_frame[13]) != ETH_P_ARP) || (ntohs(arp_hdr->opcode) != ARPOP_REPLY))
    {
        if ((ret = recv(sd, ether_frame, IP_MAXPACKET, 0)) < 0)
        {
            if (errno = EINTR)
            {
                memset(ether_frame, 0, IP_MAXPACKET * sizeof(ether_frame));
                continue;
            }
            else
            {
                perror("RecvARP.recv");
                exit(EXIT_FAILURE);
            }
        }
    }

    close(sd);

    /*
     * TODO: need to to convert this IP
     */
    printf("Someone's IP: %u.%u.%u.%u\n", arp_hdr->router_ip[0], arp_hdr->router_ip[1], arp_hdr->router_ip[2], arp_hdr->router_ip[3]);
    printf("Someone's MAC: ");
    for (i = 0; i < 5; ++i)
    {
        printf("%02x:", arp_hdr->router_mac[i]);
    }
    printf("%02x\n", arp_hdr->router_mac[5]);
    return 0;
}

/*
 * FIXME: Don't know why local variable inpack won't get malloc
 */
/*
 *int
 *recv_neighbor_advert(struct _idata *idata)
 *{
 *    int i;
 *    int sd;
 *    int status;
 *    u_int8_t *inpack;
 *    u_int8_t *pkt;
 *    struct msghdr msghdr;
 *    struct ifreq ifr;
 *
 *    inpack = allocate_ustrmem(IP_MAXPACKET);
 *
 *    memset(&msghdr, 0, sizeof(msghdr));
 *    return 0;
 *}
 */


/*
 *int
 *recv_router_advert(struct _router route)
 *{
 *}
 */

int
send_arp(struct _idata *idata, struct _scan *scan)
{
    int sd;
    int ret;
    int hdr_len;
    u_int8_t *hdr;
    struct sockaddr_ll datalink;

    memset(&datalink, 0, sizeof(datalink));

    datalink.sll_family = AF_PACKET;
    memcpy(datalink.sll_addr, idata->iface_mac, 4 * sizeof(datalink.sll_addr));
    datalink.sll_halen = 0;

    hdr_len = 6 + 6 + 2 + ARP_HDRLEN;
    hdr = craft_arp_packet(idata, scan);
    if ((sd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
    {
        perror("SendARP.socket");
        exit(EXIT_FAILURE);
    }

    if ((ret = sendto(sd, hdr, hdr_len, 0, (struct sockaddr *) &datalink, sizeof(datalink))) <= 0)
    {
        perror("SendARP.sendto");
        exit(EXIT_FAILURE);
    }

    return 0;
}

int
send_neighbor_solicit(struct _idata *idata, struct _scan *scan)
{
    //int ret;
    int sd;
    struct _neighbor *neigh;
    struct msghdr msghdr;

    memset(&neigh, 0, sizeof(neigh));
    msghdr = neighbor_solicit(idata, scan);

    if ((sd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)) < 0)
    {
        perror("SendNeighSolicit.socket");
        exit(EXIT_FAILURE);
    }

    if ((sendmsg(sd, &msghdr, 0)) != -1)
    {
        perror("SendNeighSolicit.sendmsg");
        exit(EXIT_FAILURE);
    }

    fprintf(stdout, "Neighbor Solicitation packet sent!\n");
    /*
     *if ((ret = recv_neighbor_advert(idata)) != 0)
     *{
     *    perror("SendNeighAdvert.recv_neighbor_advert");
     *    exit(EXIT_FAILURE);
     *}
     */

    fflush(stdout);
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
    struct _idata *idata;
    struct _scan *scan;

    signal(SIGINT, sigint_handler);
    signal(SIGSEGV, segfault_handler);
    idata = malloc(sizeof *idata);
    scan = malloc(sizeof *scan);
    init_idata(idata);
    init_scan(scan);

    if (argc < 2)
    {
        usage();
        exit(EXIT_FAILURE);
    }

    while ((ret = getopt_long(argc, argv, "hi:t:vVpm:ra", opts, NULL)) != -1)
    {
        switch (ret)
        {
            case 'h':
                usage(argv);
                exit(EXIT_FAILURE);

            case 'i':
                idata->iface = strdup(optarg);
                break;

            case 't':
                scan->target = strdup(optarg);
                break;

            case 'p':
                scan->ping_flag = 1;
                break;

            case 'm':
                scan->target_mac = strdup(optarg);
                break;

            case 'r':
                scan->router_flag = 1;
                break;

            case 'a':
                scan->arp_flag = 1;
                break;

            case 'V':
                banner();
                exit(EXIT_SUCCESS);

            case 'v':
                LOG_add_level(1);
                break;
        }
    }
    init_interface(idata);
    int i;
    for (i = 0; i < 5; ++i)
    {
        printf("%02x:", idata->iface_mac[i]);
    }
    printf("%02x\n", idata->iface_mac[5]);
    send_arp(idata, scan);
    exit(EXIT_FAILURE);
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

    //send_neighbor_solicit(idata, scan);
    /*
     *for (;;)
     *    recv_neighbor_advert(idata, scan);
     */

    free_idata(idata);
    free_scan(scan);
    return EXIT_SUCCESS;
}
