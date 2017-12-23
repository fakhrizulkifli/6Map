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

struct addrinfo *
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
        fprintf(stderr, "ERROR: %s:%d getaddrinfo() failed - %s\n", __func__, __LINE__, gai_strerror(status));
        //perror("Utils.getaddrinfo");
        return -1;
    }

    return res;
}

struct _idata *
init_interface(struct _idata *idata)
{
    int i, sd, ret;
    char ip6[INET6_ADDRSTRLEN];
    char ip4[INET_ADDRSTRLEN];
    struct ifreq ifr;
    struct sockaddr_in6 *ipv6;
    struct sockaddr_in *ipv4;
    struct ifaddrs *addrs, *res;

    memset(&ifr, 0, sizeof(struct ifreq));
    memset(&ipv6, 0, sizeof(struct sockaddr_in6));
    memset(&ipv4, 0, sizeof(struct sockaddr_in));
    memset(&addrs, 0, sizeof(struct ifaddrs));

    // TODO: free() all the pointers on exceptions
    if ((sd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
    {
        perror("Utils.socket");
        exit(EXIT_FAILURE);
    }

    DEBUG("DEBUG: %s:%s:%d %s\n", __FILE__, __func__, __LINE__, idata->iface);
    memcpy(ifr.ifr_name, idata->iface, sizeof(ifr.ifr_name));

    if (ioctl(sd, SIOCGIFHWADDR, &ifr) < 0)
    {
        perror("Utils.ioctl");
        return -1;
    }

    if ((idata->index = if_nametoindex(idata->iface)) == 0)
    {
        perror("Utils.if_nametoindex");
        return -1;
    }

    if ((ret = getifaddrs(&addrs)) != 0)
    {
        perror("Utils.getifaddrs");
        return -1;
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
                return -1;
            }
            memcpy(idata->iface_ip4, ip4, sizeof(idata->iface_ip4) - 1);
        }

        if (res->ifa_addr->sa_family == AF_INET6)
        {
            ipv6 = (struct sockaddr_in6 *) res->ifa_addr;
            if ((ret = inet_ntop(AF_INET6, &ipv6->sin6_addr, ip6, INET6_ADDRSTRLEN)) == NULL)
            {
                perror("Utils.inet_ntop6");
                return -1;
            }
            memcpy(idata->iface_ip6, ip6, sizeof(idata->iface_ip6) - 1);
        }
    }

    memcpy(idata->iface_mac, ifr.ifr_hwaddr.sa_data, sizeof(idata->iface_mac));

    LOG(0, "Interface: %s\n", idata->iface);
    LOG(0, "Interface MAC Address: ");
    for (i = 0; i < 5; ++i)
    {
        fprintf(stdout, "%02x:", idata->iface_mac[i]);
    }
    fprintf(stdout, "%02x\n", idata->iface_mac[5]);
    LOG(0, "Interface IPv4 Address: %s\n", idata->iface_ip4);
    LOG(0, "Interface IPv6 Address: %s\n", idata->iface_ip6);

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
