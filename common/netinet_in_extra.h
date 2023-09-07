#ifndef NETINET_IN_EXTRA_H
#define NETINET_IN_EXTRA_H

#include <netinet/in.h>

/*
 * Provide some non-standard extensions to netinet/in.h.
 *
 * These functions keep the same name and call conventions as netinet/in.h.
 */

// RFC 4291 - 2.4. Address Type Identification
#define IN6_IS_ADDR_UC_GLOBAL(a)   \
    !IN6_IS_ADDR_UNSPECIFIED(a) && \
    !IN6_IS_ADDR_LOOPBACK(a)    && \
    !IN6_IS_ADDR_MULTICAST(a)   && \
    !IN6_IS_ADDR_LINKLOCAL(a)

#endif
