/*
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
#include <sl_cpc.h>

#include "common/bus.h"
#include "common/log.h"
#include "common/hif.h"
#include "common/version.h"

// FIXME: This is global to avoid a conditional definition as a member of bus.
static cpc_handle_t g_cpc_handle;

#include "bus_cpc.h"

static void cpc_reset_callback(void)
{
    FATAL(3, "RCP reset");
}

int cpc_open(struct bus *bus, const char *cpc_instance, bool verbose)
{
    int ret, fd;

    ret = cpc_init(&g_cpc_handle, cpc_instance, verbose, cpc_reset_callback);
    FATAL_ON(ret, 2, "cpc_init: %m");
    fd = cpc_open_endpoint(g_cpc_handle, &bus->cpc_ep, SL_CPC_ENDPOINT_WISUN, 1);
    FATAL_ON(fd < 0, 2, "cpc_open_endpoint: %m");
    // ret = cpc_set_endpoint_option(bus->cpc_ep, CPC_OPTION_BLOCKING, (void *)true, sizeof(bool));
    // FATAL_ON(ret, 2, "cpc_set_endpoint_option: %m");
    return fd;
}

int cpc_tx(struct bus *bus, const void *buf, unsigned int buf_len)
{
    int ret;

    ret = cpc_write_endpoint(bus->cpc_ep, buf, buf_len, 0);
    FATAL_ON(ret < 0, 2, "cpc_write_endpoint: %m");
    TRACE(TR_HDLC, "hdlc tx: %s (%d bytes)",
        tr_bytes(buf, ret, NULL, 128, DELIM_SPACE | ELLIPSIS_STAR), ret);
    return ret;
}

int cpc_rx(struct bus *bus, void *buf, unsigned int buf_len)
{
    int ret;

    ret = cpc_read_endpoint(bus->cpc_ep, buf, buf_len, 0);
    FATAL_ON(ret < 0, 2, "cpc_read_endpoint: %m");
    TRACE(TR_HDLC, "hdlc rx: %s (%d bytes)",
        tr_bytes(buf, ret, NULL, 128, DELIM_SPACE | ELLIPSIS_STAR), ret);
    return ret;
}

uint32_t cpc_secondary_app_version(struct bus *bus)
{
    uint8_t major, patch;
    const char *str;
    uint16_t minor;
    int ret;

    str = cpc_get_secondary_app_version(g_cpc_handle);
    BUG_ON(!str);
    if (!strcmp(str, "UNDEFINED"))
        return VERSION(0, 0, 0);
    ret = sscanf(str, "%hhu.%hu.%hhu", &major, &minor, &patch);
    BUG_ON(ret == EOF);
    return VERSION(major, minor, patch);
}
