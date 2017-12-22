#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <net/ethernet.h>

#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include "logger.h"
#include "utils.h"
#include "arp.h"
#include "6map.h"

u_int8_t *
craft_arp_packet(struct _idata *idata, struct _scan *scan)
{
    u_int8_t *ether_frame;
    u_int8_t *broadcast_mac;
    struct _arp arp_hdr;

    memset(&arp_hdr, 0, sizeof(struct _arp));
    ether_frame = allocate_ustrmem(IP_MAXPACKET);
    broadcast_mac = allocate_ustrmem(6);

    memcpy(&arp_hdr.router_ip, scan->target, sizeof(u_int8_t));
    arp_hdr.htype = htons(1);
    arp_hdr.ptype = htons(ETH_P_IP);
    arp_hdr.hlen = 6;
    arp_hdr.plen = 4;
    arp_hdr.opcode = htons(ARPOP_REQUEST);

    /*
     * FIXME: Why the hell the mac address is changing?
     */
    int i;
    for (i = 0; i < 5; ++i)
    {
        printf("%02x:", idata->iface_mac[i]);
    }
    printf("%02x\n", idata->iface_mac[5]);
    memcpy(&arp_hdr.iface_mac, idata->iface_mac, 6 * sizeof(u_int8_t));
    // set as 0 as we don't know it
    memset(&arp_hdr.router_mac, 0, sizeof(u_int8_t));

    // broadcast mac address
    memset(broadcast_mac, 0xff, 6 * sizeof(u_int8_t));
    memcpy(ether_frame, broadcast_mac, 6 * sizeof(u_int8_t));
    memcpy(ether_frame + 6, broadcast_mac, sizeof(u_int8_t));

    ether_frame[12] = ETH_P_ARP / 256;
    ether_frame[13] = ETH_P_ARP % 256;

    memcpy(ether_frame + ETH_HDRLEN, &arp_hdr, ARP_HDRLEN * sizeof(u_int8_t));

    return ether_frame;
}
