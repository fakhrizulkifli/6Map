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
 * * Neither the name of utils nor the names of its
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
#include <errno.h>
#include <assert.h>
#include "logger.h"
#include "neighbor.h"
#include "6map.h"

#include <netdb.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <bits/ioctls.h>
#include <sys/types.h>
#include <linux/if_ether.h>

int
free_idata(struct _idata idata)
{
    free(idata.iface);
    free(idata.src_mac);
    free(idata.dst_mac);

    return 0;
}

int
free_scan(struct _scan scan)
{
    free(scan.dst_ip);
    free(scan.src_ip);
    free(scan.send_ether_frame);
    free(scan.recv_ether_frame);
    free(scan.icmp_recv_ip_hdr);
    free(scan.icmp_recv_icmp_hdr);

    return 0;
}

int
free_neighbor(struct _neighbor neigh)
{
    free(neigh.inpack);
    free(neigh.outpack);
    free(neigh.psdhdr);

    return 0;
}

void *
find_ancillary(struct msghdr *msg, int cmsg_type)
{
    struct cmsghdr *cmsg = NULL;

    for (cmsg = CMSG_FIRSTHDR (msg); cmsg != NULL; cmsg = CMSG_NXTHDR (msg, cmsg))
    {
        if ((cmsg->cmsg_level == IPPROTO_IPV6) && (cmsg->cmsg_type == cmsg_type))
        {
            return (CMSG_DATA (cmsg));
        }
    }
    return (NULL);
}

int
validate_ip_addr(char *ip_addr)
{
    struct sockaddr_in6 sa;

    if ((inet_pton(AF_INET6, ip_addr, &(sa.sin6_addr))) != 1)
    {
        perror("Utils.inet_pton");
        exit(EXIT_FAILURE);
    }
    return 0;
}

int
resolve_addr(char *addr)
{
    int status;
    struct addrinfo hints, *res;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET6;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = hints.ai_flags | AI_CANONNAME;

    if ((status = getaddrinfo(addr, NULL, &hints, &res)) != 0)
    {
        perror("Utils.getaddrinfo");
        exit(EXIT_FAILURE);
    }

    freeaddrinfo(res);
    return 0;
}

struct _idata
init_interface(struct _idata idata)
{
    int i;
    int sd;
    struct ifreq ifr;

    memset(&ifr, 0, sizeof(struct ifreq));
    if ((sd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
    {
        perror("Utils.socket");
        exit(EXIT_FAILURE);
    }

    memcpy(ifr.ifr_name, idata.iface, sizeof(ifr.ifr_name));
    if (ioctl(sd, SIOCGIFHWADDR, &ifr) < 0)
    {
        perror("Utils.ioctl");
        exit(EXIT_FAILURE);
    }

    if ((idata.index = if_nametoindex(idata.iface)) == 0)
    {
        perror("Utils.if_nametoindex");
        exit(EXIT_FAILURE);
    }

    memcpy(&idata.src_mac, ifr.ifr_hwaddr.sa_data, sizeof(u_int8_t));
    LOG(1, "Interface: %s\n", idata.iface);
    LOG(1, "MAC Address: ");
    for (i = 0; i < 5; ++i)
    {
        LOG(1, "%02x:", &idata.src_mac[i]);
    }
    LOG(1, "%02x\n", &idata.src_mac[5]);

    return idata;
}

u_int16_t
checksum(u_int16_t *addr, int len)
{
    int count = len;
    register u_int32_t sum = 0;
    u_int16_t answer = 0;

    while (count > 1)
    {
        sum += *(addr++);
        count -= 2;
    }

    if (count > 1)
    {
        sum += *(u_int8_t *) addr;
    }

    while (sum >> 16)
    {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    answer = ~sum;
    return answer;
}

char *
allocate_strmem(int len)
{
    void *tmp;

    if (len <= 0)
    {
        fprintf(stderr, "ERROR: Cannot allocate memory because len = %i in allocate_strmem().\n", len);
        exit(EXIT_FAILURE);
    }

    tmp = malloc(len * sizeof(char));
    assert(tmp != NULL);
    memset(tmp, 0, len * sizeof(char));
    return tmp;
}

u_int8_t *
allocate_ustrmem(int len)
{
    void *tmp;

    if (len <= 0)
    {
        fprintf(stderr, "ERROR: Cannot allocate memory because len = %i in allocate_ustrmem().\n", len);
        exit(EXIT_FAILURE);
    }

    tmp = malloc(len * sizeof(u_int8_t));
    assert(tmp != NULL);
    memset(tmp, 0, len * sizeof(u_int8_t));
    return tmp;
}
