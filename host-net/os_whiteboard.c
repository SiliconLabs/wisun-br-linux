#include <platform/os_whiteboard.h>
#include <mbed-client-libservice/ip6string.h>

#include "host-common/log.h"
#include "os_whiteboard.h"

void whiteboard_os_modify(const uint8_t address[static 16], enum add_or_remove mode)
{
    char tmp[MAX_IPV6_STRING_LEN_WITH_TRAILING_NULL];

    ip6tos(address, tmp);
    if (mode == ADD)
        DEBUG("Add %s to neighbor table", tmp);
    if (mode == REMOVE)
        DEBUG("Remove %s from neighbor table", tmp);
}

