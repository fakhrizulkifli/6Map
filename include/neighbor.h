#ifndef NEIGHBOR_H
#define NEIGHBOR_H

#include <netinet/in.h>

struct _pktinfo6
{
    struct in6_addr ipi6_addr;
    unsigned int ipi6_ifindex;
};

struct _neighbor
{
    int recvadvert_flag;
    u_int8_t *inpack;
    u_int8_t *outpack;
    u_int8_t *psdhdr;
    u_int8_t hoplimit;
};

struct msghdr neighbor_solicit();

#endif
