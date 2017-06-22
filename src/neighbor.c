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
neighbor_solicit(struct _idata *idata, struct _scan *scan)
{
    int cmsglen;
    int psdhdrlen;
    u_int8_t *psdhdr;
    u_int8_t *outpack;
    u_int8_t hoplimit;
    struct nd_neighbor_solicit *ns;
    struct _pktinfo6 *pktinfo;
    struct msghdr msghdr;
    struct iovec iov[2];
    struct cmsghdr *cmsghdr1, *cmsghdr2;
    int NS_HDRLEN = sizeof(struct nd_neighbor_solicit);
    struct sockaddr_in6 src, dst;

    outpack = allocate_ustrmem(IP_MAXPACKET);
    psdhdr = allocate_ustrmem(IP_MAXPACKET);

    fprintf(stdout, "Crafting Neighbor Solicitation packet...\n");
    if (resolve_addr(idata->iface_ip6) == 0)
    {
        memset(&src, 0, sizeof(src));
        memcpy(&src, idata->iface_ip6, sizeof(src));
        memcpy(psdhdr, src.sin6_addr.s6_addr, 16 * sizeof(psdhdr));
    }

    if (resolve_addr(scan->target) == 0)
    {
        memset(&dst, 0, sizeof(dst));
        memcpy(&dst, scan->target, sizeof(dst));
        fprintf(stdout, "Target Address: %s\n", scan->target);
    }

/*
 *    dstsnmc.sin6_addr.s6_addr[0] = 255;
 *    dstsnmc.sin6_addr.s6_addr[1] = 2;
 *    for (i = 2; i < 11; ++i)
 *    {
 *        dstsnmc.sin6_addr.s6_addr[i] = 0;
 *    }
 *    dstsnmc.sin6_addr.s6_addr[11] = 1;
 *    dstsnmc.sin6_addr.s6_addr[12] = 255;
 *
 *    [> FIXME: solicited-node address wrong calculation <]
 *    ipv6 = (struct sockaddr_in6 *) &dstsnmc;
 *    //memset(scan->target, 0, INET6_ADDRSTRLEN * sizeof(scan->target));
 *    if (inet_ntop(AF_INET6, &ipv6->sin6_addr, scan->target, INET6_ADDRSTRLEN) == NULL)
 *    {
 *        perror("Neighbor.inet_ntop");
 *        exit(EXIT_FAILURE);
 *    }
 *
 *    fprintf(stdout, "Target Multicast Address: %s\n", scan->target);
 *    memcpy(psdhdr + 16, dstsnmc.sin6_addr.s6_addr, 16 * sizeof(psdhdr));
 */

    ns = (struct nd_neighbor_solicit *) outpack;
    memset(ns, 0 ,sizeof(struct nd_neighbor_solicit));

    ns->nd_ns_hdr.icmp6_type = ND_NEIGHBOR_SOLICIT;
    ns->nd_ns_hdr.icmp6_code = 0;
    ns->nd_ns_hdr.icmp6_cksum = htons(0);
    ns->nd_ns_target = dst.sin6_addr;

    memcpy(outpack + NS_HDRLEN, &idata->iface_mac, 6 * sizeof(outpack));

    psdhdrlen = 8 + 8 + 4 + 3 + 1 + NS_HDRLEN + 6;

    memset(&msghdr, 0, sizeof(msghdr));
    msghdr.msg_name = &dst;
    msghdr.msg_namelen = sizeof(dst);
    memset(&iov, 0, sizeof(struct iovec));
    iov[0].iov_base = (u_int8_t *) outpack;
    iov[0].iov_len = NS_HDRLEN + 6;
    msghdr.msg_iov = iov;
    msghdr.msg_iovlen = 1;

    cmsglen = CMSG_SPACE (sizeof (int)) + CMSG_SPACE (sizeof(pktinfo));
    msghdr.msg_control = allocate_ustrmem(cmsglen);
    msghdr.msg_controllen = cmsglen;

    hoplimit = 255u;
    cmsghdr1 = CMSG_FIRSTHDR (&msghdr);
    cmsghdr1->cmsg_level = IPPROTO_IPV6;
    cmsghdr1->cmsg_type = IPV6_HOPLIMIT;
    cmsghdr1->cmsg_len = CMSG_LEN(sizeof(int));
    *(CMSG_DATA (cmsghdr1)) = hoplimit;

    cmsghdr2 = CMSG_NXTHDR (&msghdr, cmsghdr1);
    cmsghdr2->cmsg_level = IPPROTO_IPV6;
    cmsghdr2->cmsg_type = IPV6_PKTINFO;
    cmsghdr2->cmsg_len = CMSG_LEN(sizeof(pktinfo));
    pktinfo = (struct _pktinfo6 *) CMSG_DATA(cmsghdr2);
    pktinfo->ipi6_ifindex = idata->index;

    psdhdr[32] = 0;
    psdhdr[33] = 0;
    psdhdr[34] = (NS_HDRLEN + 6) / 256;
    psdhdr[35] = (NS_HDRLEN + 6) % 256;
    psdhdr[36] = 0;
    psdhdr[37] = 0;
    psdhdr[38] = 0;
    psdhdr[39] = IPPROTO_ICMPV6;
    memcpy(psdhdr + 40, outpack, (NS_HDRLEN + 6) * sizeof(psdhdr));
    ns->nd_ns_hdr.icmp6_cksum = checksum((u_int16_t *) psdhdr, psdhdrlen);

    fprintf(stdout, "Checksum: %x\n", ntohs(ns->nd_ns_hdr.icmp6_cksum));

    fflush(stdout);
    return msghdr;
}

