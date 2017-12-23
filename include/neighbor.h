#ifndef NEIGHBOR_H
#define NEIGHBOR_H

#include <netinet/in.h>
#include "6map.h"

struct _pktinfo6
{
    struct in6_addr ipi6_addr;
    unsigned int ipi6_ifindex;
};

struct _neighbor
{
    int recvadvert_flag;
};

int neighbor_solicit(struct _idata *, struct _scan *);
int recv_neighbor_advert(struct _idata *, struct _scan *);
int neighbor_advert(struct _idata *, struct _scan *);

#endif
