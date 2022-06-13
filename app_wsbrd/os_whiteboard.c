/*
 * Copyright (c) 2021-2022 Silicon Laboratories Inc. (www.silabs.com)
 *
 * The licensor of this software is Silicon Laboratories Inc. Your use of this
 * software is governed by the terms of the Silicon Labs Master Software License
 * Agreement (MSLA) available at [1].  This software is distributed to you in
 * Object Code format and/or Source Code format and is governed by the sections
 * of the MSLA applicable to Object Code, Source Code and Modified Open Source
 * Code. By using this software, you agree to the terms of the MSLA.
 *
 * [1]: https://www.silabs.com/about-us/legal/master-software-license-agreement
 */
#include <stack/mac/platform/os_whiteboard.h>
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

