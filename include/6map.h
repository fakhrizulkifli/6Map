#ifndef SIXMAP_H
#define SIXMAP_H

#define VERSION "0.1"
#define ALL_NODES_MULTICAST_ADDR "FF02::1"
#define ALL_ROUTERS_MULTICAST_ADDR "FF02::2"
#define ALL_SPF_ROUTERS_MULTICAST_ADDR "FF02::5"
#define ALL_DR_ROUTERS_MULTICAST_ADDR "FF02::6"
#define ALL_RIP_ROUTERS_MULTICAST_ADDR "FF02::9"
#define ALL_EIGRP_ROUTERS_MULTICAST_ADDR "FF02::a"
#define ALL_PIM_ROUTERS_MULTICAST_ADDR "FF02::d"
#define ALL_MLDV2_MULTICAST_ADDR "FF02::16"
#define ALL_DHCP_SERVERS_RELAY_AGENT_MULTICAST_ADDR "FF02::1:2"
#define ALL_DHCP_SERVERS_MULTICAST_ADDR "FF05::1:3"
#define ALL_LLMNR_MULTICAST_ADDR "FF02::1:3"

#define SPOOF_NEIGHBOR_ADVERT   (0x1)
#define SPOOF_ROUTER_ADVERT     (0x2)
#define SEND_ROUTER_SOLICIT     (0x4)
#define SEND_NEIGHBOR_SOLICIT   (0x8)
#define SPOOF_ENABLED           (0x16)

#define TRACE_SIZE  256

struct _idata
{
    char iface[10];
    char iface_ip6[50];
    char iface_ip4[20];
    char iface_mac[50];
    int index;
};

struct _scan
{
    char target[50];
    char port[5];
    char target_mac[50];
};

#endif
