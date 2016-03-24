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

#include <netdb.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <ifaddrs.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <bits/ioctls.h>
#include <sys/types.h>
#include <linux/if_ether.h>
#include "logger.h"
#include "neighbor.h"
#include "6map.h"

int
init_idata(struct _idata *idata)
{
    idata->iface = malloc(sizeof(idata->iface));
    idata->iface_ip6 = malloc(sizeof(idata->iface_ip6));
    idata->iface_ip4 = malloc(sizeof(idata->iface_ip4));
    idata->iface_mac = malloc(sizeof(idata->iface_mac));

    memset(&idata, 0, sizeof(idata));
    return 0;
}

int
init_scan(struct _scan *scan)
{
    scan->target = malloc(sizeof(scan->target));
    scan->port = malloc(sizeof(scan->port));
    scan->target_mac = malloc(sizeof(scan->target_mac));

    memset(&scan, 0, sizeof(scan));
    return 0;
}

int
free_idata(struct _idata *idata)
{
    /*
     * FIXME: Free unsigned char *iface_mac
     */
    free(idata->iface);
    free(idata->iface_ip6);
    free(idata->iface_ip4);

    return 0;
}

int
free_scan(struct _scan *scan)
{
    free(scan->target);
    free(scan->port);
    free(scan->target_mac);

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

    memset(&hints, 0, sizeof(hints));
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

int
init_interface(struct _idata *idata)
{
    int i;
    int sd;
    int ret;
    char ip6[INET6_ADDRSTRLEN];
    char ip4[INET_ADDRSTRLEN];
    struct ifreq ifr;
    struct sockaddr_in6 *ipv6;
    struct sockaddr_in *ipv4;
    struct ifaddrs *addrs, *res;

    memset(&ifr, 0, sizeof(ifr));
    memset(&ipv6, 0, sizeof(ipv6));
    memset(&ipv4, 0, sizeof(ipv4));
    memset(&addrs, 0, sizeof(addrs));
    if ((sd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
    {
        perror("Utils.socket");
        exit(EXIT_FAILURE);
    }

    memcpy(ifr.ifr_name, idata->iface, sizeof(ifr.ifr_name));
    if (ioctl(sd, SIOCGIFHWADDR, &ifr) < 0)
    {
        perror("Utils.ioctl");
        exit(EXIT_FAILURE);
    }

    if ((idata->index = if_nametoindex(idata->iface)) == 0)
    {
        perror("Utils.if_nametoindex");
        exit(EXIT_FAILURE);
    }

    if ((ret = getifaddrs(&addrs)) != 0)
    {
        perror("Utils.getifaddrs");
        exit(EXIT_FAILURE);
    }

    for (res = addrs; res != NULL; res = res->ifa_next)
    {
        if (res->ifa_addr == NULL)
            continue;

        if ((res->ifa_flags & IFF_UP) == 0)
            continue;

        if (strncmp(res->ifa_name, idata->iface, strlen(idata->iface)) != 0)
            continue;

        if (res->ifa_addr->sa_family == AF_INET)
        {
            ipv4 = (struct sockaddr_in *) res->ifa_addr;
            if ((ret = inet_ntop(AF_INET, &ipv4->sin_addr, ip4, INET_ADDRSTRLEN)) == NULL)
            {
                perror("Utils.inet_ntop4");
                exit(EXIT_FAILURE);
            }
            idata->iface_ip4 = strdup(ip4);
        }

        if (res->ifa_addr->sa_family == AF_INET6)
        {
            ipv6 = (struct sockaddr_in6 *) res->ifa_addr;
            if ((ret = inet_ntop(AF_INET6, &ipv6->sin6_addr, ip6, INET6_ADDRSTRLEN)) == NULL)
            {
                perror("Utils.inet_ntop6"); /* FIXME: Detailed error output using __LINE__ */
                exit(EXIT_FAILURE);
            }
            idata->iface_ip6 = strdup(ip6);
        }
    }

    memcpy(&idata->iface_mac, ifr.ifr_hwaddr.sa_data, sizeof(idata->iface_mac));
    idata->iface_mac = (unsigned char *) &ifr.ifr_addr.sa_data;
    fprintf(stdout, "Interface: %s\n", idata->iface);
    fprintf(stdout, "Interface MAC Address: ");
    for (i = 0; i < 5; ++i)
    {
        fprintf(stdout, "%02x:", idata->iface_mac[i]);
    }
    fprintf(stdout, "%02x\n", idata->iface_mac[5]);
    fprintf(stdout, "Interface IPv4 Address: %s\n", idata->iface_ip4);
    fprintf(stdout, "Interface IPv6 Address: %s\n", idata->iface_ip6);

    fflush(stdout);
    return 0;
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
