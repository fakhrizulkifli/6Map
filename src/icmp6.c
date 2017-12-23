#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "logger.h"
#include "icmp6.h"
#include "utils.h"
#include "6map.h"

#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/tcp.h>

#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <sys/socket.h>
#include <sys/types.h>

int
send_icmp(struct _idata *idata, struct _scan *scan)
{
    int ret, datalen, sd, cmsglen, hoplimit, psdhdrlen;
    uint8_t *data, *outpack, *psdhdr;

    struct icmp6_hdr *icmphdr;
    struct addrinfo *res;
    struct sockaddr_in6 src, dst;
    struct msghdr msghdr;
    struct cmsghdr *cmsghdr1, *cmsghdr2;
    struct _pktinfo6 *pktinfo;
    struct iovec iov[2];

    data = allocate_ustrmem(IP_MAXPACKET);
    outpack = allocate_ustrmem(IP_MAXPACKET);
    psdhdr = allocate_ustrmem(IP_MAXPACKET);

    LOG(0, "Crafting IPv6 ICMP packet...\n");
    LOG(0, "Index for interface %s is %i\n", idata->iface, idata->index);

    if ((res = resolve_addr(idata->iface_ip6)) == -1)
    {
        fprintf(stderr, "ERROR: %s:%d resolve_addr failed\n", __func__, __LINE__);
        return -1;
    }

    memset(&src, 0, sizeof(struct sockaddr_in6));
    memcpy(&src, res->ai_addr, res->ai_addrlen);
    memcpy(psdhdr, src.sin6_addr.s6_addr, 16);

    freeaddrinfo(res);

    if ((res = resolve_addr(scan->target)) == -1)
    {
        fprintf(stderr, "ERROR: %s:%d resolve_addr failed\n", __func__, __LINE__);
        return -1;
    }

    memset(&dst, 0, sizeof(struct sockaddr_in6));
    memcpy(&dst, res->ai_addr, res->ai_addrlen);
    memcpy(psdhdr + 16, dst.sin6_addr.s6_addr, 16);

    freeaddrinfo(res);

    icmphdr = (struct icmp6_hdr *) outpack;
    memset(icmphdr, 0, ICMP_HDRLEN * sizeof(uint8_t));
    icmphdr->icmp6_type = ICMP6_ECHO_REQUEST;
    icmphdr->icmp6_code = 0;
    icmphdr->icmp6_cksum = 0;
    icmphdr->icmp6_id = htons(5);
    icmphdr->icmp6_seq = htons(300);

    datalen = 10;
    memset(data, 0, sizeof(uint8_t) * datalen);

    memcpy(outpack + ICMP_HDRLEN, data, datalen);

    psdhdrlen = 16 + 16 + 4 + 3 + 1 + ICMP_HDRLEN + datalen;

    memset(&msghdr, 0, sizeof(struct msghdr));
    msghdr.msg_name = &dst;
    msghdr.msg_namelen = sizeof(struct sockaddr_in6);

    memset(&iov, 0, sizeof(struct iovec));
    iov[0].iov_base = (uint8_t *) outpack;
    iov[0].iov_len = ICMP_HDRLEN + datalen;
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
    pktinfo->ipi6_addr = src.sin6_addr;

    psdhdr[32] = 0;
    psdhdr[33] = 0;
    psdhdr[34] = (ICMP_HDRLEN + datalen) / 256;
    psdhdr[35] = (ICMP_HDRLEN + datalen) % 256;
    psdhdr[36] = 0;
    psdhdr[37] = 0;
    psdhdr[38] = 0;
    psdhdr[39] = IPPROTO_ICMPV6;
    memcpy(psdhdr + 40, outpack, ICMP_HDRLEN + datalen);
    icmphdr->icmp6_cksum = checksum((uint16_t *) psdhdr, psdhdrlen);

    LOG(0, "Checksum: %x\n", ntohs(icmphdr->icmp6_cksum));

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
    free(data);
    free(psdhdr);
    free(msghdr.msg_control);

    return 0;
}
