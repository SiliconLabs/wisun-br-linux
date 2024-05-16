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
#ifndef BUS_CPC_H
#define BUS_CPC_H
#include <stdint.h>
#include "common/log.h"

struct bus;

#ifdef HAVE_LIBCPC
#include <assert.h>
#include <sl_cpc.h>

// For some reason these CPC types are declared as a struct containing only a
// void pointer, instead of simply being void pointers, which makes casting
// awful if they are not stored with their exact type.
static_assert(sizeof(cpc_endpoint_t) == sizeof(void *));
static_assert(sizeof(cpc_handle_t) == sizeof(void *));
#else
typedef void *cpc_endpoint_t;
typedef void *cpc_handle_t;
#endif

struct bus_cpc {
    cpc_endpoint_t endpoint;
    cpc_handle_t handle;
};

#ifdef HAVE_LIBCPC

int cpc_open(struct bus *bus, const char *instance_name, bool verbose);
int cpc_tx(struct bus *bus, const void *buf, unsigned int buf_len);
int cpc_rx(struct bus *bus, void *buf, unsigned int buf_len);
uint32_t cpc_secondary_app_version(struct bus *bus);

#else

static inline int cpc_open(struct bus *bus, const char *instance_name, bool verbose)
{
    FATAL(1, "support for CPC is disabled");
}

static inline int cpc_tx(struct bus *bus, const void *buf, unsigned int buf_len)
{
    return -1;
}

static inline int cpc_rx(struct bus *bus, void *buf, unsigned int buf_len)
{
    return -1;
}

static inline uint32_t cpc_secondary_app_version(struct bus *bus)
{
    return 0;
}

#endif

#endif
