#ifndef ICMP_H
#define ICMP_H

#define ETH_HDRLEN 14
#define IP6_HDRLEN 40
#define ICMP_HDRLEN 8

#include "6map.h"

int send_icmp(struct _idata *, struct _scan *);

#endif
