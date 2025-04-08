#ifndef NS3_SL_WISUN_TYPES_H
#define NS3_SL_WISUN_TYPES_H

#include <netinet/in.h>

// Prevent Silicon Labs socket.h from being included.
#define __SOCKET_H__

typedef struct in6_addr in6_addr_t;

// FIXME: sl_wisun_types.h includes sl_status.h indirectly from socket.h.
#include <sl_status.h>

#include_next <sl_wisun_types.h>

#endif
