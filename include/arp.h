#ifndef ARP_H
#define ARP_H

#include "6map.h"

struct _arp
{
    u_int16_t htype;
    u_int16_t ptype;
    u_int16_t opcode;
    u_int8_t hlen;
    u_int8_t plen;
    u_int8_t router_mac[6];
    u_int8_t router_ip[4];
    u_int8_t iface_ip[4];
    u_int8_t iface_mac[6];
};

#define ETH_HDRLEN 14
#define IP4_HDRLEN 20
#define ARP_HDRLEN 28
#define ARPOP_REQUEST 1
#define ARPOP_REPLY 2

u_int8_t *craft_arp_packet(struct _idata *, struct _scan *);

#endif
