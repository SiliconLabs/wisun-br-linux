/*
 * SPDX-License-Identifier: LicenseRef-MSLA
 * Copyright (c) 2021-2023 Silicon Laboratories Inc. (www.silabs.com)
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
#ifndef COMMON_OS_TYPES_H
#define COMMON_OS_TYPES_H
#include <stdint.h>
#include <stdbool.h>

#include "bus_cpc.h"
#include "bus_uart.h"

struct slist;

struct bus {
    int  (*tx)(struct bus *bus, const void *buf, unsigned int len);
    int  (*rx)(struct bus *bus, void *buf, unsigned int len);

    int     fd;
    int     spinel_tid;
    int     spinel_iid;
    struct bus_uart uart;
    struct bus_cpc cpc;
};

#endif
