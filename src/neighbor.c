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
neighbor_solicit(struct _idata *idata, struct _scan *scan)
{
    socklen_t srclen;
    int i, sd, ret, optlen, cmsglen, psdhdrlen;
    uint8_t *psdhdr, *outpack, *options, hoplimit;

    struct addrinfo *res;
    struct nd_neighbor_solicit *ns;
    struct _pktinfo6 *pktinfo;
    struct msghdr msghdr;
    struct iovec iov[2];
    struct cmsghdr *cmsghdr1, *cmsghdr2;
    struct sockaddr_in6 src, dst, dstsnmc, *ipv6;   // TODO: remove temporary *ipv6

    int NS_HDRLEN = sizeof(struct nd_neighbor_solicit);

    optlen = 8;
    outpack = allocate_ustrmem(IP_MAXPACKET);
    psdhdr = allocate_ustrmem(IP_MAXPACKET);
    options = allocate_ustrmem(optlen);

    LOG(0, "Crafting Neighbor Solicitation packet...\n");

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
    memcpy(psdhdr, src.sin6_addr.s6_addr, 16 * sizeof(uint8_t));

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
    memset(&dstsnmc, 0, sizeof(struct sockaddr_in6));
    memcpy(&dst, res->ai_addr, res->ai_addrlen);
    memcpy(&dstsnmc, res->ai_addr, res->ai_addrlen);

    LOG(0, "Target Address: %s\n", scan->target);

    memset(scan->target, 0, INET6_ADDRSTRLEN * sizeof(char));
    ipv6 = (struct sockaddr_in6 *) res->ai_addr;
    if ((ret = inet_ntop(AF_INET6, &ipv6->sin6_addr, scan->target, INET6_ADDRSTRLEN)) == NULL)
    {
        free(outpack);
        free(psdhdr);
        free(msghdr.msg_control);

        fprintf(stderr, "ERROR: %s:%d inet_ntop failed\n", __func__, __LINE__);
        return -1;
    }
    freeaddrinfo(res);
    LOG(0, "Target Unicast IPv6 Address: %s\n", scan->target);

    dstsnmc.sin6_addr.s6_addr[0] = 255;
    dstsnmc.sin6_addr.s6_addr[1] = 2;

    for (i = 2; i < 11; i++)
    {
        dstsnmc.sin6_addr.s6_addr[i] = 0;
    }
    dstsnmc.sin6_addr.s6_addr[11] = 1;
    dstsnmc.sin6_addr.s6_addr[12] = 255;

    memset(scan->target, 0, INET6_ADDRSTRLEN * sizeof(char));
    ipv6 = (struct sockaddr_in6 *) &dstsnmc;
    if ((ret = inet_ntop(AF_INET6, &ipv6->sin6_addr, scan->target, INET6_ADDRSTRLEN)) == NULL)
    {
        free(outpack);
        free(psdhdr);
        free(msghdr.msg_control);

        fprintf(stderr, "ERROR: %s:%d inet_ntop failed\n", __func__, __LINE__);
        return -1;
    }
    LOG(0, "Target solicited-node multicast address: %s\n", scan->target);

    memcpy(psdhdr + 16, dstsnmc.sin6_addr.s6_addr, 16 * sizeof(uint8_t));

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

    LOG(0, "Soliciting interface MAC address: ");

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

    ns = (struct nd_neighbor_solicit *) outpack;
    memset(ns, 0, sizeof(struct nd_neighbor_solicit));

    ns->nd_ns_hdr.icmp6_type = ND_NEIGHBOR_SOLICIT;
    ns->nd_ns_hdr.icmp6_code = 0;
    ns->nd_ns_hdr.icmp6_cksum = htons(0);
    ns->nd_ns_reserved = htonl(0);
    ns->nd_ns_target = dst.sin6_addr;

    memcpy(outpack + NS_HDRLEN, options, optlen * sizeof(uint8_t));

    psdhdrlen = 16 + 16 + 4 + 3 + 1 + NS_HDRLEN + optlen;

    memset(&msghdr, 0, sizeof(struct msghdr));
    msghdr.msg_name = &dstsnmc;
    msghdr.msg_namelen = sizeof(struct sockaddr_in6);

    memset(&iov, 0, sizeof(struct iovec));
    iov[0].iov_base = (uint8_t *) outpack;
    iov[1].iov_len = NS_HDRLEN + optlen;
    msghdr.msg_iov = iov;
    msghdr.msg_iovlen = 1;

    cmsglen = CMSG_SPACE(sizeof(int)) + CMSG_SPACE(sizeof(struct _pktinfo6));
    msghdr.msg_control = allocate_ustrmem(cmsglen);
    msghdr.msg_controllen = cmsglen;

    hoplimit = 255u;
    cmsghdr1 = CMSG_FIRSTHDR(&msghdr);
    cmsghdr1->cmsg_level = IPPROTO_IPV6;
    cmsghdr1->cmsg_type = IPV6_HOPLIMIT;
    cmsghdr1->cmsg_len = CMSG_LEN(sizeof(int));
    *(CMSG_DATA(cmsghdr1)) = hoplimit;

    cmsghdr2 = CMSG_NXTHDR(&msghdr, cmsghdr1);
    cmsghdr2->cmsg_level = IPPROTO_IPV6;
    cmsghdr2->cmsg_type = IPV6_PKTINFO;
    cmsghdr2->cmsg_len = CMSG_LEN(sizeof(struct _pktinfo6));
    pktinfo = (struct _pktinfo6 *) CMSG_DATA(cmsghdr2);
    pktinfo->ipi6_ifindex = idata->index;

    psdhdr[32] = 0;
    psdhdr[33] = 0;
    psdhdr[34] = (NS_HDRLEN + optlen) / 256;
    psdhdr[35] = (NS_HDRLEN + optlen) % 256;
    psdhdr[36] = 0;
    psdhdr[37] = 0;
    psdhdr[38] = 0;
    psdhdr[39] = IPPROTO_ICMPV6;

    memcpy(psdhdr + 40, outpack, (NS_HDRLEN + optlen) * sizeof(uint8_t));
    ns->nd_ns_hdr.icmp6_cksum = checksum((uint16_t *) psdhdr, psdhdrlen);

    LOG(1, "Checksum: %x\n", ntohs(ns->nd_ns_hdr.icmp6_cksum));

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
recv_neighbor_advert(struct _idata *idata, struct _scan *scan)
{
    int i, sd, ret, hoplimit, on;
    uint8_t *inpack, *pkt, *opt;
    int len;

    struct nd_neighbor_advert *na;
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
    msghdr.msg_controllen = IP_MAXPACKET + sizeof(uint8_t);

    if ((sd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)) < 0)
    {
        fprintf(stderr, "ERROR: %s:%d socket failed\n", __func__, __LINE__);
        return -1;
    }

    on = 1;
    if ((ret = setsockopt(sd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &on, sizeof(int))) < 0)
    {
        fprintf(stderr, "ERROR: %s:%d setsockopt failed\n", __func__, __LINE__);
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
    if (ioctl(sd, SIOCGIFHWADDR, &ifr) < 0)
    {
        fprintf(stderr, "ERROR: %s:%d ioctl failed\n", __func__, __LINE__);
        return -1;
    }

    LOG(1, "On this node, index for interface %s is %i\n", idata->iface, idata->index);

    if (setsockopt(sd, SOL_SOCKET, SO_BINDTODEVICE, (void *) &ifr, sizeof(struct ifreq)) < 0)
    {
        fprintf(stderr, "ERROR: %s:%d SO_BINDTODEVICE failed\n", __func__, __LINE__);
        return -1;
    }

    LOG(0, "Listening to incoming message...\n");
    na = (struct nd_neighbor_advert *) inpack;
    while (na->nd_na_hdr.icmp6_type != ND_NEIGHBOR_ADVERT)
    {
        if ((len = recvmsg(sd, &msghdr, 0)) < 0)
        {
            fprintf(stderr, "ERROR: %s:%d recvmsg failed\n", __func__, __LINE__);
            return -1;
        }
    }

    fprintf(stdout, "IPV6 header data: ");
    opt = find_ancillary(&msghdr, IPV6_HOPLIMIT);

    if (opt == NULL)
    {
        fprintf(stderr, "ERROR: %s:%d unknown hop limit\n", __func__, __LINE__);
        return -1;
    }
    hoplimit = *(int *) opt;
    LOG(0, "Hop Limit: %i\n", hoplimit);

    opt = find_ancillary(&msghdr, IPV6_PKTINFO);

    if (opt == NULL)
    {
        fprintf(stderr, "ERROR: %s:%d unknown destination address\n", __func__, __LINE__);
        return -1;
    }

    LOG(0, "Receiving address: %s\n", idata->iface_ip6);

    LOG(0, "Receiving interface index: %i\n", idata->index);

    LOG(0, "ICMPv6 header data:\n");
    LOG(0, "Type: %u\n", na->nd_na_hdr.icmp6_type);
    LOG(0, "Code: %u\n", na->nd_na_hdr.icmp6_code);
    LOG(0, "Checksum: %x\n", ntohs(na->nd_na_hdr.icmp6_cksum));
    LOG(0, "Router flag: %u\n", ntohl(na->nd_na_flags_reserved) >> 31);
    LOG(0, "Solicited flag: %u\n", (ntohl(na->nd_na_flags_reserved) >> 30) & 1);
    LOG(0, "Override flag: %u\n", (ntohl(na->nd_na_flags_reserved) >> 29) & 1);
    LOG(0, "Reserved: %i\n", ntohl(na->nd_na_flags_reserved) & 536870911u);

    if ((ret = inet_ntop(AF_INET6, &(na->nd_na_target), scan->target, INET6_ADDRSTRLEN)) == NULL)
    {
        fprintf(stderr, "ERROR: %s:%d inet_ntop - %s", __func__, __LINE__, strerror(ret));
        return -1;
    }

    LOG(0, "Target address of neighbor solicitation: %s\n", scan->target);
    LOG(0, "Options:\n");

    pkt = (uint8_t *) inpack;
    LOG(0, "Type: %u\n", pkt[sizeof(struct nd_neighbor_advert)]);
    LOG(0, "Length: %u (units of 8 octets)\n", pkt[sizeof(struct nd_neighbor_advert) + 1]);

    fprintf(stdout, "MAC Addres: ");

    for (i = 0; i < 5; i++)
    {
        fprintf(stdout, "%02x:", pkt[sizeof(struct nd_neighbor_advert) + i]);
    }
    fprintf(stdout, "%02x\n", pkt[sizeof(struct nd_neighbor_advert) + 7]);

    close(sd);

    free(inpack);
    free(msghdr.msg_control);

    return 0;
}

int
neighbor_advert(struct _idata *idata, struct _scan *scan)
{
    int i, sd, ret, cmsglen, psdhdrlen;
    int optlen = 8;
    int NA_HDRLEN = sizeof(struct nd_neighbor_advert);
    uint8_t *outpack, *options, *psdhdr, hoplimit;

    struct addrinfo *res;
    struct sockaddr_in6 src, dst;
    struct nd_neighbor_advert *na;
    struct msghdr msghdr;
    struct cmsghdr *cmsghdr1, *cmsghdr2;
    struct _pktinfo6 *pktinfo;
    struct iovec iov[2];

    outpack = allocate_ustrmem(IP_MAXPACKET);
    options = allocate_ustrmem(optlen);
    psdhdr = allocate_ustrmem(IP_MAXPACKET);

    LOG(0, "Crafting Neighbor Advertisement packet...\n");

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
        free(psdhdr);
        free(msghdr.msg_control);

        fprintf(stderr, "ERROR: %s:%d resolve_addr failed\n", __func__, __LINE__);
        return -1;
    }

    memset(&dst, 0, sizeof(struct sockaddr_in6));
    memcpy(&dst, res->ai_addr, res->ai_addrlen);
    memcpy(psdhdr + 16, dst.sin6_addr.s6_addr, 16 * sizeof(uint8_t));

    freeaddrinfo(res);

    options[0] = 2;
    options[1] = optlen / 8;

    for (i = 0; i < 6; i++)
    {
        options[i+2] = (uint8_t) idata->iface_mac[i];
    }

    fprintf(stdout, "Advertising node's MAC address for interface %s is ", idata->iface);

    for (i = 0; i < 5; i++)
    {
        fprintf(stdout, "%02x:", options[i+2]);
    }
    fprintf(stdout, "%02x\n", options[5+2]);

    LOG(1, "Advertising node's index for interface %s is %i\n", idata->iface, idata->index);

    na = (struct nd_neighbor_advert *) outpack;
    memset(na, 0, sizeof(struct nd_neighbor_advert));

    na->nd_na_hdr.icmp6_type = ND_NEIGHBOR_ADVERT;
    na->nd_na_hdr.icmp6_code = 0;
    na->nd_na_hdr.icmp6_cksum = htons(0);
    na->nd_na_flags_reserved = htonl((1 << 30) + (1 << 29));
    na->nd_na_target = src.sin6_addr;

    memcpy(outpack + NA_HDRLEN, options, optlen * sizeof(uint8_t));

    psdhdrlen = 16 + 16 + 4 + 3 + 1 + NA_HDRLEN + optlen;

    memset(&msghdr, 0, sizeof(struct msghdr));
    msghdr.msg_name = &dst;
    msghdr.msg_namelen = sizeof(struct sockaddr_in6);

    memset(&iov, 0, sizeof(struct iovec));
    iov[0].iov_base = (uint8_t *) outpack;
    iov[0].iov_len = NA_HDRLEN + optlen;
    msghdr.msg_iov = iov;
    msghdr.msg_iovlen = 1;

    cmsglen = CMSG_SPACE(sizeof(int)) + CMSG_SPACE(sizeof(struct _pktinfo6));
    msghdr.msg_control = allocate_ustrmem(cmsglen);
    msghdr.msg_controllen = cmsglen;

    hoplimit = 255u;
    cmsghdr1 = CMSG_FIRSTHDR(&msghdr);
    cmsghdr1->cmsg_level = IPPROTO_IPV6;
    cmsghdr1->cmsg_type = IPV6_HOPLIMIT;
    cmsghdr1->cmsg_len = CMSG_LEN(sizeof(int));
    *(CMSG_DATA(cmsghdr1)) = hoplimit;

    cmsghdr2 = CMSG_NXTHDR(&msghdr, cmsghdr1);
    cmsghdr2->cmsg_level = IPPROTO_IPV6;
    cmsghdr2->cmsg_type = IPV6_PKTINFO;
    cmsghdr2->cmsg_len = CMSG_LEN(sizeof(struct _pktinfo6));
    pktinfo = (struct _pktinfo6 *) CMSG_DATA(cmsghdr2);
    pktinfo->ipi6_ifindex = idata->index;

    psdhdr[32] = 0;
    psdhdr[33] = 0;
    psdhdr[34] = (NA_HDRLEN + optlen) / 256;
    psdhdr[35] = (NA_HDRLEN + optlen) % 256;
    psdhdr[36] = 0;
    psdhdr[37] = 0;
    psdhdr[38] = 0;
    psdhdr[39] = IPPROTO_ICMPV6;
    memcpy(psdhdr + 40, outpack, (NA_HDRLEN + optlen) * sizeof(uint8_t));
    na->nd_na_hdr.icmp6_cksum = checksum((uint16_t *) psdhdr, psdhdrlen);

    LOG(1, "Checksum: %x\n", ntohs(na->nd_na_hdr.icmp6_cksum));

    if ((sd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)) < 0)
    {
        fprintf(stderr, "ERROR: %s:%d socket failed\n", __func__, __LINE__);
        return -1;
    }

    if (sendmsg(sd, &msghdr, 0) < 0)
    {
        fprintf(stderr, "ERROR: %s:%d sendmsg failed", __func__, __LINE__);
        return -1;
    }

    close(sd);

    free(outpack);
    free(options);
    free(psdhdr);
    free(msghdr.msg_control);

    return 0;
}
