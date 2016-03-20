#ifndef UTILS_H
#define UTILS_H

#include "neighbor.h"
#include "6map.h"

int init_idata(struct _idata *);
int init_scan(struct _scan *);
int init_interface(struct _idata *, struct _scan *);
int free_scan(struct _scan *);
int free_idata(struct _idata *);
void *find_ancillary(struct msghdr *, int);
int validate_ip_addr(u_int8_t);
int resolve_addr(char *);
u_int16_t checksum(u_int16_t *, int);
char *allocate_strmem(int);
u_int8_t *allocate_ustrmem(int);

#endif
