#include <platform/os_whiteboard.h>
#include <mbed-client-libservice/ip6string.h>

#include "log.h"

void whiteboard_os_modify(const uint8_t address[static 16], enum add_or_remove mode)
{
    char tmp[MAX_IPV6_STRING_LEN_WITH_TRAILING_NULL];

    ip6tos(address, tmp);
    if (mode == ADD)
        TRACE("Add %s to neighbor table", tmp);
    if (mode == REMOVE)
        TRACE("Remove %s from neighbor table", tmp);
}

