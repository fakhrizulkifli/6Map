#ifndef UTILS_H
#define UTILS_H

#include "neighbor.h"
#include "6map.h"

struct addrinfo *resolve_addr(char *);
struct _idata *init_interface(struct _idata *);

void *find_ancillary(struct msghdr *, int);
int validate_ip_addr(u_int8_t);
uint16_t checksum(u_int16_t *, int);
char *allocate_strmem(int);
uint8_t *allocate_ustrmem(int);

#endif
