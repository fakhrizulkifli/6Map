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

/*
 *void
 *icmp_packet(struct _idata idata, struct _scan scan)
 *{
 *}
 */
