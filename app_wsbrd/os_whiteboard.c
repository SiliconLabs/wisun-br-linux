#include <nanostack/mac/platform/os_whiteboard.h>
#include <stack-services/ip6string.h>

#include "common/log.h"
#include "os_whiteboard.h"

void whiteboard_os_modify(const uint8_t address[static 16], enum add_or_remove mode)
{
    if (mode == ADD)
        DEBUG("Add %s to neighbor table", tr_ipv6(address));
    if (mode == REMOVE)
        DEBUG("Remove %s from neighbor table", tr_ipv6(address));
}

