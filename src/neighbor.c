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
 * * Neither the name of neighbor nor the names of its
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
#include <unistd.h>

#include <netdb.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/icmp6.h>

#include <sys/ioctl.h>
#include <bits/ioctls.h>
#include <bits/socket.h>
#include "logger.h"
#include "neighbor.h"
#include "utils.h"
#include "6map.h"

struct msghdr
neighbor_solicit(struct _neighbor *neigh, struct _idata *idata, struct _scan *scan)
{
    int i;
    int cmsglen;
    int psdhdrlen;
    struct nd_neighbor_solicit *ns;
    struct _pktinfo6 *pktinfo;
    struct msghdr msghdr;
    struct iovec iov[2];
    struct cmsghdr *cmsghdr1, *cmsghdr2;
    int NS_HDRLEN = sizeof(struct nd_neighbor_solicit);
    struct sockaddr_in6 *ipv6, src, dst, dstsnmc;

    neigh = malloc(sizeof *neigh);
    init_neighbor(neigh);
    neigh->outpack = allocate_ustrmem(IP_MAXPACKET);
    neigh->psdhdr = allocate_ustrmem(IP_MAXPACKET);

    if (resolve_addr(idata->iface_ip) == 0)
    {
        memset(&src, 0, sizeof(src));
        memcpy(&src, scan->target, sizeof(socklen_t));
        memcpy(&neigh->psdhdr, scan->target, 16 * sizeof(u_int8_t));
    }

    if (resolve_addr(scan->target) == 0)
    {
        memset(&dst, 0, sizeof(dst));
        memset(&dstsnmc, 0, sizeof(dstsnmc));
        memcpy(&dst, scan->target, sizeof(socklen_t));
        memcpy(&dstsnmc, scan->target, sizeof(socklen_t));
    }

    LOG(1, "Target Unicast IPv6 address: %s\n", scan->target);

    dstsnmc.sin6_addr.s6_addr[0] = 255;
    dstsnmc.sin6_addr.s6_addr[1] = 2;
    for (i = 2; i < 11; ++i)
    {
        dstsnmc.sin6_addr.s6_addr[i] = 0;
    }
    dstsnmc.sin6_addr.s6_addr[11] = 1;
    dstsnmc.sin6_addr.s6_addr[12] = 255;

    /* FIXME: solicited-node address wrong calculation */
    ipv6 = (struct sockaddr_in6 *) &dstsnmc;
    //memset(scan.dst_ip, 0, sizeof(struct _neighbor));
    if (inet_ntop(AF_INET6, &(ipv6->sin6_addr), scan->target, INET6_ADDRSTRLEN) == NULL)
    {
        perror("Neighbor.inet_ntop");
        exit(EXIT_FAILURE);
    }

    LOG(1, "Target Solicited-Node Multicast address: %s\n", scan->target);
    memcpy(&neigh->psdhdr + 16, dstsnmc.sin6_addr.s6_addr, 16 * sizeof(u_int8_t));

    ns = (struct nd_neighbor_solicit *) &neigh->outpack;
    memset(ns, 0 ,sizeof(struct nd_neighbor_solicit));

    ns->nd_ns_hdr.icmp6_type = ND_NEIGHBOR_SOLICIT;
    ns->nd_ns_hdr.icmp6_code = 0;
    ns->nd_ns_hdr.icmp6_cksum = htons(0);
    ns->nd_ns_target = dst.sin6_addr;

    memcpy(&neigh->outpack + NS_HDRLEN, &idata->iface_mac, 6 * sizeof(u_int8_t));

    psdhdrlen = 16 + 16 + 4 + 3 + 1 + NS_HDRLEN + 6;

    memset(&msghdr, 0, sizeof(msghdr));
    msghdr.msg_name = &dstsnmc;
    msghdr.msg_namelen = sizeof(dstsnmc);
    memset(&iov, 0, sizeof(struct iovec));
    iov[0].iov_base = (u_int8_t *) &neigh->outpack;
    iov[0].iov_len = NS_HDRLEN + 6;
    msghdr.msg_iov = iov;
    msghdr.msg_iovlen = 1;

    cmsglen = CMSG_SPACE (sizeof (int)) + CMSG_SPACE (sizeof(pktinfo));
    msghdr.msg_control = allocate_ustrmem(cmsglen);
    msghdr.msg_controllen = cmsglen;

    neigh->hoplimit = 255u;
    cmsghdr1 = CMSG_FIRSTHDR (&msghdr);
    cmsghdr1->cmsg_level = IPPROTO_IPV6;
    cmsghdr1->cmsg_type = IPV6_HOPLIMIT;
    cmsghdr1->cmsg_len = CMSG_LEN(sizeof(int));
    *(CMSG_DATA (cmsghdr1)) = neigh->hoplimit;

    cmsghdr2 = CMSG_NXTHDR (&msghdr, cmsghdr1);
    cmsghdr2->cmsg_level = IPPROTO_IPV6;
    cmsghdr2->cmsg_type = IPV6_PKTINFO;
    cmsghdr2->cmsg_len = CMSG_LEN(sizeof(pktinfo));
    pktinfo = (struct _pktinfo6 *) CMSG_DATA(cmsghdr2);
    pktinfo->ipi6_ifindex = idata->index;

    neigh->psdhdr[32] = 0;
    neigh->psdhdr[33] = 0;
    neigh->psdhdr[34] = (NS_HDRLEN + 6) / 256;
    neigh->psdhdr[35] = (NS_HDRLEN + 6) % 256;
    neigh->psdhdr[36] = 0;
    neigh->psdhdr[37] = 0;
    neigh->psdhdr[38] = 0;
    neigh->psdhdr[39] = IPPROTO_ICMPV6;
    memcpy(&neigh->psdhdr + 40, &neigh->outpack, (NS_HDRLEN + 6) * sizeof(u_int8_t));
    ns->nd_ns_hdr.icmp6_cksum = checksum((u_int16_t *) &neigh->psdhdr, psdhdrlen);

    fprintf(stdout, "Checksum: %x\n", ntohs(ns->nd_ns_hdr.icmp6_cksum));

    fflush(stdout);
    return msghdr;
}

