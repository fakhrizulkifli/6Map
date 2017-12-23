#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <signal.h>
#include <unistd.h>
#include <execinfo.h>
#include <errno.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/tcp.h>

#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <sys/ioctl.h>
#include <bits/ioctls.h>
#include <bits/socket.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include "6map.h"
#include "logger.h"
#include "neighbor.h"
#include "utils.h"

#define TRACE_SIZE 256

const struct option opts[] =
{
    {"help", no_argument, 0, 'h'},
    {"interface", required_argument, 0, 'i'},
    {"target", required_argument, 0, 't'},
    {"router", no_argument, 0, 'r'},
    {"neighbor", no_argument, 0, 'n'},
    {"version", no_argument, 0, 'V'},
    {"verbose", no_argument, 0, 'v'},
    {NULL, 0, NULL, 0}
};

void
usage()
{
    printf("Usage: ./6map options\n");
    printf("OPTIONS:\n\t");
    printf("-h, --help\thelp\n\t");
    printf("-i, --iface\tinterface\n\t");
    printf("-t, --target\ttarget IPv6 address\n\t");
    printf("-r, --router\trouter discovery mode\n\t");
    printf("-n, --neigbor\tneighbor discovery mode\n\t");
    printf("-V, --version\tversion\n\t");
    printf("-v, --verbose\tverbose\n");
}

void
banner()
{
    printf("6map v%s -- IPv6 Mapper\n", VERSION);
    printf("Copyright (c) 2017 Fakhri Zulkifli\n");
    printf("<mohdfakhrizulkifli at gmail dot com>\n");
}

static void
segfault_handler(int sig)
{
    void *func[TRACE_SIZE];
    char **symb = NULL;
    int size, i;

    size = backtrace(func, TRACE_SIZE);
    symb = backtrace_symbols(func, size);

    for (i = 0; i < size; ++i)
    {
        fprintf(stderr, "[bt]: %s\n", symb[i]);
    }
    fflush(stderr);
    free(symb);
    exit(sig);
}

static void
sigint_handler(int sig)
{
    fprintf(stderr, "Ctrl-c detected!\n");
    fflush(stderr);
    exit(sig);
}

int
send_neighbor_solicit(struct _idata *idata, struct _scan *scan)
{
    int ret;

    if ((ret = neighbor_solicit(idata, scan)) == -1)
    {
        free(idata);
        free(scan);
        fprintf(stderr, "ERROR: %s:%d neighbor_solicit failed\n", __func__, __LINE__);
        exit(EXIT_FAILURE);
    }

    LOG(0, "Neighbor Solicitation packet sent!\n");
    if ((ret = recv_neighbor_advert(idata, scan)) == -1)
    {
        free(idata);
        free(scan);
        fprintf(stderr, "ERROR: %s:%d recv_neighbor_advert failed\n",  __func__, __LINE__);
        exit(EXIT_FAILURE);
    }

    return 0;
}

int
send_router_solicit(struct _idata *idata, struct _scan *scan)
{
    int ret;

    if ((ret = router_solicit(idata, scan)) == -1)
    {
        free(idata);
        free(scan);
        fprintf(stderr, "ERROR: %s:%d router_solicit failed\n", __func__, __LINE__);
        exit(EXIT_FAILURE);
    }

    LOG(0, "Router Solicitation packet sent!\n");
    if ((ret = recv_router_advert(idata)) == -1)
    {
        free(idata);
        free(scan);
        fprintf(stderr, "ERROR: %s:%d recv_router_advert failed\n", __func__, __LINE__);
        exit(EXIT_FAILURE);
    }

    return 0;
}

int
spoof_router_advertisement(struct _idata *idata, struct _scan *scan)
{
    int ret;

    if ((ret = router_advert(idata, scan)) == -1)
    {
        free(idata);
        free(scan);
        fprintf(stderr, "ERROR: %s:%d router_advert failed\n", __func__, __LINE__);
        exit(EXIT_FAILURE);
    }
    return 0;
}

int
spoof_neighbor_advertisement(struct _idata *idata, struct _scan *scan)
{
    int ret;

    if ((ret = neighbor_advert(idata, scan)) == -1)
    {
        free(idata);
        free(scan);
        fprintf(stderr, "ERROR: %s:%d neighbor_advert failed", __func__, __LINE__);
        exit(EXIT_FAILURE);
    }

    return 0;
}

int
main(int argc, char **argv)
{
    int ret;
    int status;
    struct _idata *idata;
    struct _scan *scan;

    signal(SIGINT, sigint_handler);
    signal(SIGSEGV, segfault_handler);

    idata = (struct _idata *) malloc(sizeof(struct _idata));
    scan = (struct _scan *) malloc(sizeof(struct _scan));

    if (argc < 2)
    {
        usage();
        exit(EXIT_FAILURE);
    }

    while ((ret = getopt_long(argc, argv, "hi:t:vVm:rn", opts, NULL)) != -1)
    {
        switch (ret)
        {
            case 'h':
                usage();
                exit(EXIT_FAILURE);

            case 'i':
                strncpy(idata->iface, optarg, sizeof(idata->iface) - 1);
                break;

            case 't':
                strncpy(scan->target, optarg, sizeof(scan->target) - 1);
                break;

            case 'n':
                scan->neighbor_flag = 1;
                break;

            case 'r':
                scan->router_flag = 1;
                break;

            case 'V':
                banner();
                exit(EXIT_SUCCESS);

            case 'v':
                LOG_add_level(1);
                break;

            default:
                usage();
                exit(EXIT_FAILURE);
        }
    }

    if (isValidIPv6(scan->target) < 1)
    {
        free(idata);
        free(scan);

        usage();
        exit(EXIT_FAILURE);
    }

    if ((idata = init_interface(idata)) == -1)
    {
        free(idata);
        free(scan);
        exit(EXIT_FAILURE);
    }

    //send_neighbor_solicit(idata, scan);
    //send_router_solicit(idata, scan);
    spoof_neighbor_advertisement(idata, scan);
    //spoof_router_advertisement(idata, scan);
    //spoof_icmp(idata, scan);

    free(idata);
    free(scan);
    exit(EXIT_FAILURE);
}
