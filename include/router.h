#ifndef ROUTER_H
#define ROUTER_H

#include <netinet/in.h>
#include "6map.h"

struct _pktinfo6
{
    struct in6_addr ipi6_addr;
    unsigned int ipi6_ifindex;
};

struct _router
{
    int recvadvert_flag;
};

int router_solicit(struct _idata *, struct _scan *);
int recv_router_advert(struct _idata *, struct _scan *);
int router_advertisement(struct _idata *, struct _scan *);

#endif
