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

int
router_solicit(struct _idata *idata, struct _scan *scan)
{
    int i, sd, ret, cmsglen, hoplimit, psdhdrlen;
    int optlen = 8;
    int RS_HDRLEN = sizeof(struct nd_router_solicit);
    socklen_t srclen;
    uint8_t *outpack, *psdhdr, *options;

    struct addrinfo *res;
    struct sockaddr_in6 src, dst, *ipv6;    // TODO: remove temporary *ipv6
    struct nd_router_solicit *rs;
    struct msghdr msghdr;
    struct cmsghdr *cmsghdr1, *cmsghdr2;
    struct _pktinfo6 *pktinfo;
    struct iovec iov[2];

    outpack = allocate_ustrmem(IP_MAXPACKET);
    psdhdr = allocate_ustrmem(IP_MAXPACKET);
    options = allocate_ustrmem(optlen);

    LOG(0, "Crafting Router Solicitation packet...\n");

    if ((res = resolve_addr(idata->iface_ip6)) == -1)
    {
        free(outpack);
        free(psdhdr);
        free(msghdr.msg_control);

        fprintf(stderr, "ERROR: %s:%d resolve_addr failed\n", __func__, __LINE__);
        return -1;
    }

    memset(&src, 0, sizeof(struct sockaddr_in6));
    memcpy(&src, res->ai_addr, res->ai_addrlen);
    srclen = res->ai_addrlen;
    memcpy(psdhdr, src.sin6_addr.s6_addr, 16 * sizeof(uint8_t));    // Copy to check pseudo-header

    freeaddrinfo(res);

    if ((res = resolve_addr(scan->target)) == -1)
    {
        free(outpack);
        free(psdhdr);
        free(msghdr.msg_control);

        fprintf(stderr, "ERROR: %s:%d resolve_addr failed\n", __func__, __LINE__);
        return -1;
    }

    memset(&dst, 0, sizeof(struct sockaddr_in6));
    memcpy(&dst, res->ai_addr, res->ai_addrlen);
    memcpy(psdhdr + 16, dst.sin6_addr.s6_addr, 16 * sizeof(uint8_t));

    ipv6 = (struct sockaddr_in6 *) res->ai_addr;
    memset(scan->target, 0, INET6_ADDRSTRLEN * sizeof(char));
    if ((ret = inet_ntop(AF_INET6, &ipv6->sin6_addr, scan->target, INET6_ADDRSTRLEN)) == NULL)
    {
        free(outpack);
        free(psdhdr);
        free(msghdr.msg_control);

        fprintf(stderr, "ERROR: %s:%d inet_ntop failed\n", __func__, __LINE__);
        return -1;
    }

    freeaddrinfo(res);
    LOG(0, "Sending to IPv6 \"all routers\" multicast address: %s\n", scan->target);

    if ((sd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)) < 0)
    {
        free(outpack);
        free(psdhdr);
        free(msghdr.msg_control);

        fprintf(stderr, "ERROR: %s:%d socket failed\n", __func__, __LINE__);
        return -1;
    }

    options[0] = 1;
    options[1] = optlen / 8;

    for (i = 0; i < 6; i++)
    {
        options[i+2] = (uint8_t) idata->iface_mac[i];
    }

    fprintf(stdout, "Soliciting interface MAC address: ");

    for (i = 0; i < 5; i++)
    {
        fprintf(stdout, "%02x:", idata->iface_mac[i]);
    }
    fprintf(stdout, "%02x\n", idata->iface_mac[5]);

    if (!(psdhdr[0] == 0xfe))
    {
        if (bind(sd, (struct sockaddr *) &src, srclen) < 0)
        {
            free(outpack);
            free(psdhdr);
            free(msghdr.msg_control);

            fprintf(stderr, "ERROR: %s:%d bind failed\n", __func__, __LINE__);
            return -1;
        }
    }

    LOG(1, "Soliciting node's index for interface %s is %i\n", idata->iface, idata->index);

    rs = (struct nd_router_solicit *) outpack;
    memset(rs, 0, sizeof(struct nd_router_solicit));

    rs->nd_rs_hdr.icmp6_type = ND_ROUTER_SOLICIT;
    rs->nd_rs_hdr.icmp6_code = 0;
    rs->nd_rs_hdr.icmp6_cksum = htons(0);
    rs->nd_rs_reserved = htonl(0);

    memcpy(outpack + RS_HDRLEN, options, optlen * sizeof(uint8_t));

    psdhdrlen = 16 + 16 + 4 + 3 + 1 + RS_HDRLEN + optlen;

    memset(&msghdr, 0, sizeof(struct msghdr));
    msghdr.msg_name = &dst;
    msghdr.msg_namelen = sizeof(struct sockaddr_in6);

    memset(&iov, 0, sizeof(struct iovec));
    iov[0].iov_base = (uint8_t *) outpack;
    iov[0].iov_len = RS_HDRLEN + optlen;

    msghdr.msg_iov = iov;
    msghdr.msg_iovlen = 1;

    cmsglen = CMSG_SPACE(sizeof(int)) + CMSG_SPACE(sizeof(struct _pktinfo6));
    msghdr.msg_control = allocate_ustrmem(cmsglen);
    msghdr.msg_controllen = cmsglen;

    hoplimit = 255;
    cmsghdr1 = CMSG_FIRSTHDR(&msghdr);
    cmsghdr1->cmsg_level = IPPROTO_IPV6;
    cmsghdr1->cmsg_type = IPV6_HOPLIMIT;
    cmsghdr1->cmsg_len = CMSG_LEN(sizeof(int));
    *((int *) CMSG_DATA(cmsghdr1)) = hoplimit;

    cmsghdr2 = CMSG_NXTHDR(&msghdr, cmsghdr1);
    cmsghdr2->cmsg_level = IPPROTO_IPV6;
    cmsghdr2->cmsg_type = IPV6_PKTINFO;
    cmsghdr2->cmsg_len = CMSG_LEN(sizeof(struct _pktinfo6));
    pktinfo = (struct _pktinfo6 *) CMSG_DATA(cmsghdr2);

    psdhdr[32] = 0;
    psdhdr[33] = 0;
    psdhdr[34] = (RS_HDRLEN + optlen) / 256;
    psdhdr[35] = (RS_HDRLEN + optlen) % 256;
    psdhdr[36] = 0;
    psdhdr[37] = 0;
    psdhdr[38] = 0;
    psdhdr[39] = IPPROTO_ICMPV6;
    memcpy(psdhdr + 40, outpack, (RS_HDRLEN + optlen) * sizeof(uint8_t));
    rs->nd_rs_hdr.icmp6_cksum = checksum((uint16_t *) psdhdr, psdhdrlen);

    LOG(1, "Checksum: %x\n", ntohs(rs->nd_rs_hdr.icmp6_cksum));

    if (sendmsg(sd, &msghdr, 0) < 0)
    {
        free(outpack);
        free(psdhdr);
        free(msghdr.msg_control);

        fprintf(stderr, "ERROR: %s:%d sendmsg failed\n", __func__, __LINE__);
        return -1;
    }

    close(sd);

    free(outpack);
    free(psdhdr);
    free(msghdr.msg_control);
    return 0;
}

int
recv_router_advert(struct _idata *idata, struct _scan *scan)
{
    int i, ret, sd, on, hoplimit;
    uint8_t *inpack, *opt, *pkt;
    int len;

    struct nd_router_advert *ra;
    struct msghdr msghdr;
    struct iovec iov[2];
    struct in6_addr dst;
    struct ifreq ifr;

    inpack = allocate_ustrmem(IP_MAXPACKET);

    memset(&msghdr, 0, sizeof(struct msghdr));
    msghdr.msg_name = NULL;
    msghdr.msg_namelen = 0;

    memset(&iov, 0, sizeof(struct iovec));
    iov[0].iov_base = (uint8_t *) inpack;
    iov[0].iov_len = IP_MAXPACKET;
    msghdr.msg_iov = iov;
    msghdr.msg_iovlen = 1;

    msghdr.msg_control = allocate_ustrmem(IP_MAXPACKET);
    msghdr.msg_controllen = IP_MAXPACKET * sizeof(uint8_t);

    if ((sd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)) < 0)
    {
        fprintf(stderr, "ERROR: %s:%d socket failed\n", __func__, __LINE__);
        return -1;
    }

    on = 1;
    if ((ret = setsockopt(sd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(int))) < 0)
    {
        fprintf(stderr, "ERROR: %s:%d setsockopt failed\n", __func__, __LINE__);
        return -1;
    }

    memset(&ifr, 0, sizeof(struct ifreq));
    memcpy(ifr.ifr_name, idata->iface, sizeof(ifr.ifr_name));
    if ((ioctl(sd, SIOCGIFHWADDR, &ifr)) < 0)
    {
        fprintf(stderr, "ERROR: %s:%d ioctl failed\n", __func__, __LINE__);
        return -1;
    }

    LOG(1, "On this node, index for interface %s is %i\n", idata->iface, idata->index);

    if ((ret = setsockopt(sd, SOL_SOCKET, SO_BINDTODEVICE, (void *) &ifr, sizeof(struct ifreq))) < 0)
    {
        fprintf(stderr, "ERROR: %s:%d setsockopt failed - %s", __func__, __LINE__, strerror(ret));
        return -1;
    }

    LOG(0, "Listening for incoming messages...\n");
    ra = (struct nd_router_advert *) inpack;
    while (ra->nd_ra_hdr.icmp6_type != ND_ROUTER_ADVERT)
    {
        if ((len = recvmsg(sd, &msghdr, 0)) < 0)
        {
            fprintf(stderr, "ERROR: %s:%d recvmsg failed", __func__, __LINE__);
            return -1;
        }
    }

    LOG(0, "IPv6 header data:\n");
    opt = find_ancillary(&msghdr, IPV6_HOPLIMIT);
    if (opt == NULL)
    {
        fprintf(stderr, "ERROR: %s:%d unknown hop limit", __func__, __LINE__);
        return -1;
    }
    hoplimit = *(int *) opt;
    LOG(0, "Hop limit: %i\n", hoplimit);

    opt = find_ancillary(&msghdr, IPV6_PKTINFO);
    if (opt == NULL)
    {
        fprintf(stderr, "ERROR: %s:%d unknown destination address\n", __func__, __LINE__);
        return -1;
    }

    LOG(0, "Receiving address: %s\n", idata->iface_ip6);

    LOG(0, "Receiving interface index: %i\n", idata->index);

    LOG(0, "ICMPv6 header data:\n");
    LOG(0, "Type (134 = router advertisement): %u\n", ra->nd_ra_hdr.icmp6_type);
    LOG(0, "Code: %u\n", ra->nd_ra_hdr.icmp6_code);
    LOG(0, "Checksum: %x\n", ntohs(ra->nd_ra_hdr.icmp6_cksum));
    LOG(0, "Hop limit recommended by this router (0 is no recommendation): %u\n", ra->nd_ra_curhoplimit);
    LOG(0, "Managed address configuration flag: %u\n", ra->nd_ra_flags_reserved >> 7);
    LOG(0, "Other stateful configuration flag: %u\n", (ra->nd_ra_flags_reserved >> 6) & 1);
    LOG(0, "Mobile home agent flag: %u\n", (ra->nd_ra_flags_reserved >> 5) & 1);
    LOG(0, "Router lifetime as default router (s): %u\n", ntohs(ra->nd_ra_router_lifetime));
    LOG(0, "Reachable time (ms): %u\n", ntohl(ra->nd_ra_reachable));
    LOG(0, "Retransmission time (ms): %u\n", ntohl(ra->nd_ra_retransmit));

    LOG(0, "Options:\n");
    pkt = (uint8_t *) inpack;
    LOG(0, "Type: %u\n", pkt[sizeof(struct nd_router_advert)]);
    LOG(0, "Length: %u (units of 8 octects)\n", pkt[sizeof(struct nd_router_advert) + 1]);

    fprintf(stdout, "MAC address: ");

    for (i = 2; i < 7; i++)
    {
        fprintf(stdout, "%02x:", pkt[sizeof(struct nd_router_advert) + i]);
    }
    fprintf(stdout, "%02x\n", pkt[sizeof(struct nd_router_advert) + 7]);

    close(sd);

    free(inpack);
    free(msghdr.msg_control);

    return 0;
}

int
router_advert(struct _idata *idata, struct _scan *scan)
{
    int i, sd, ret, cmsglen, hoplimit, psdhdrlen;
    int RA_HDRLEN = sizeof(struct nd_router_advert);
    int optlen = 8;
    uint8_t *outpack, *options, *psdhdr;

    struct addrinfo *res;
    struct sockaddr_in6 src, dst, *ipv6;    // TODO: remove temporary *ipv6
    struct nd_router_advert *ra;
    struct cmsghdr *cmsghdr1, *cmsghdr2;
    struct msghdr msghdr;
    struct _pktinfo6 *pktinfo;
    struct iovec iov[2];

    outpack = allocate_ustrmem(IP_MAXPACKET);
    options = allocate_ustrmem(optlen);
    psdhdr = allocate_ustrmem(IP_MAXPACKET);

    LOG(0, "Crafting Router Advertisement packet...\n");

    if ((res = resolve_addr(idata->iface_ip6)) == -1)
    {
        free(outpack);
        free(options);
        free(psdhdr);

        fprintf(stderr, "ERROR: %s:%d resolve_addr failed\n", __func__, __LINE__);
        return -1;
    }

    memset(&src, 0, sizeof(struct sockaddr_in6));
    memcpy(&src, res->ai_addr, res->ai_addrlen);
    memcpy(psdhdr, src.sin6_addr.s6_addr, 16 * sizeof(uint8_t));

    freeaddrinfo(res);

    if ((res = resolve_addr(scan->target)) == -1)
    {
        free(outpack);
        free(options);
        free(psdhdr);

        fprintf(stderr, "ERROR: %s:%d resolve_addr failed\n", __func__, __LINE__);
        return -1;
    }

    memset(&dst, 0, sizeof(struct sockaddr_in6));
    memcpy(&dst, res->ai_addr, res->ai_addrlen);
    memcpy(psdhdr + 16, dst.sin6_addr.s6_addr, 16 * sizeof(uint8_t));

    ipv6 = (struct sockaddr_in6 *) res->ai_addr;
    memset(scan->target, 0, INET6_ADDRSTRLEN * sizeof(char));
    if ((ret = inet_ntop(AF_INET6, &ipv6->sin6_addr, scan->target, INET6_ADDRSTRLEN)) == NULL)
    {
        fprintf(stderr, "ERROR: %s:%d inet_ntop failed\n", __func__, __LINE__);
        return -1;
    }

    LOG(0, "Sending to IPv6 unicast address: %s\n", scan->target);
    freeaddrinfo(res);

    options[0] = 1;
    options[1] = optlen / 8;

    for (i = 0; i < 6; i++)
    {
        options[i+2] = (uint8_t) idata->iface_mac[i];
    }

    fprintf(stdout, "MAC address for interface %s is ", idata->iface);
    for (i = 0; i < 5; i++)
    {
        fprintf(stdout, "%02x:", options[i+2]);
    }
    fprintf(stdout, "%02x\n", options[5+2]);

    LOG(1, "Advertising node's index for interface %s is %i\n", idata->iface, idata->index);

    ra = (struct nd_router_advert *) outpack;
    memset(ra, 0, sizeof(struct nd_router_advert));

    ra->nd_ra_hdr.icmp6_type = ND_ROUTER_ADVERT;
    ra->nd_ra_hdr.icmp6_code = 0;
    ra->nd_ra_hdr.icmp6_cksum = htons(0);
    ra->nd_ra_curhoplimit = 0;
    ra->nd_ra_flags_reserved = (1 << 7) + (0 << 6) + (0 << 5);
    ra->nd_ra_reachable = htons(5000);
    ra->nd_ra_retransmit = htonl(1000);

    memcpy(outpack + RA_HDRLEN, options, optlen * sizeof(uint8_t));

    psdhdrlen = 16 + 16 + 4 + 3 + 1 + RA_HDRLEN + optlen;

    memset(&msghdr, 0, sizeof(struct msghdr));
    msghdr.msg_name = &dst;
    msghdr.msg_namelen = sizeof(struct sockaddr_in6);

    memset(&iov, 0, sizeof(struct iovec));
    iov[0].iov_base = (uint8_t *) outpack;
    iov[0].iov_len = RA_HDRLEN + optlen;
    msghdr.msg_iov = iov;
    msghdr.msg_iovlen = 1;

    cmsglen = CMSG_SPACE(sizeof(int)) + CMSG_SPACE(sizeof(struct _pktinfo6));
    msghdr.msg_control = allocate_ustrmem(cmsglen);
    msghdr.msg_controllen = cmsglen;

    hoplimit = 255;
    cmsghdr1 = CMSG_FIRSTHDR(&msghdr);
    cmsghdr1->cmsg_level = IPPROTO_IPV6;
    cmsghdr1->cmsg_type = IPV6_HOPLIMIT;
    cmsghdr1->cmsg_len = CMSG_LEN(sizeof(int));
    *((int *) CMSG_DATA(cmsghdr1)) = hoplimit;

    cmsghdr2 = CMSG_NXTHDR(&msghdr, cmsghdr1);
    cmsghdr2->cmsg_level = IPPROTO_IPV6;
    cmsghdr2->cmsg_type = IPV6_PKTINFO;
    cmsghdr2->cmsg_len = CMSG_LEN(sizeof(struct _pktinfo6));
    pktinfo = (struct _pktinfo6 *) CMSG_DATA(cmsghdr2);
    pktinfo->ipi6_ifindex = idata->index;

    psdhdr[32] = 0;
    psdhdr[33] = 0;
    psdhdr[34] = (RA_HDRLEN + optlen) / 256;
    psdhdr[35] = (RA_HDRLEN + optlen) % 256;
    psdhdr[36] = 0;
    psdhdr[37] = 0;
    psdhdr[38] = 0;
    psdhdr[39] = IPPROTO_ICMPV6;
    memcpy(psdhdr + 40, outpack, (RA_HDRLEN + optlen) * sizeof(uint8_t));
    ra->nd_ra_hdr.icmp6_cksum = checksum((uint16_t *) psdhdr, psdhdrlen);

    LOG(1, "Checksum: %x\n", ntohs(ra->nd_ra_hdr.icmp6_cksum));

    if ((sd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)) < 0)
    {
        fprintf(stderr, "ERROR: %s:%d socket failed\n", __func__, __LINE__);
        return -1;
    }

    if (sendmsg(sd, &msghdr, 0) < 0)
    {
        fprintf(stderr, "ERROR: %s:%d sendmsg failed\n", __func__, __LINE__);
        return -1;
    }

    close(sd);

    free(outpack);
    free(options);
    free(psdhdr);
    free(msghdr.msg_control);

    return 0;
}
