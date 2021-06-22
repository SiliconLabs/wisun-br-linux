/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
#include <stdint.h>
#include <stdbool.h>

#include "nanostack/source/Core/include/ns_monitor.h"

bool ns_monitor_packet_allocation_allowed(void)
{
    return true;
}

