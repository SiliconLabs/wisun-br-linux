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
#include <stddef.h>

#include "common/hif.h"
#include "common/iobuf.h"
#include "common/log.h"
#include "common/memutils.h"

#include "spinel.h"

const char *spinel_cmd_str(int cmd)
{
    #define cmd_name(name) { #name, SPINEL_CMD_##name }
    static const struct {
        char *str;
        int val;
    } spinel_cmds[] = {
        cmd_name(PROP_IS),
        cmd_name(PROP_SET),
        cmd_name(PROP_GET),
        cmd_name(NOOP),
        cmd_name(RESET),
        cmd_name(REPLAY_TIMERS),
        cmd_name(REPLAY_INTERFACE),
    };

    for (int i = 0; i < ARRAY_SIZE(spinel_cmds); i++)
        if (cmd == spinel_cmds[i].val)
            return spinel_cmds[i].str;
    return NULL;
}

const char *spinel_prop_str(int prop)
{
    #define prop_name(name) { #name, SPINEL_PROP_##name }
    static const struct {
        char *str;
        int val;
    } spinel_props[] = {
        { "-", -1 },
        prop_name(FRAME),
        prop_name(HWADDR),
        prop_name(LAST_STATUS),
        prop_name(MAC_15_4_PANID),
        prop_name(MAC_15_4_SADDR),
        prop_name(PHY_CHAN),
        prop_name(PHY_TX_POWER),
        prop_name(RF_CONFIG),
        prop_name(STREAM_RAW),
        prop_name(STREAM_STATUS),
        prop_name(WS_15_4_MODE),
        prop_name(WS_ACCEPT_BYPASS_UNKNOW_DEVICE),
        prop_name(WS_ACK_WAIT_DURATION),
        prop_name(WS_ASSOCIATION_PERMIT),
        prop_name(WS_ASYNC_FRAGMENTATION),
        prop_name(WS_AUTO_REQUEST_KEY_ID_MODE),
        prop_name(WS_AUTO_REQUEST_KEY_INDEX),
        prop_name(WS_AUTO_REQUEST_KEY_SOURCE),
        prop_name(WS_AUTO_REQUEST_SECURITY_LEVEL),
        prop_name(WS_BEACON_PAYLOAD),
        prop_name(WS_BEACON_PAYLOAD_LENGTH),
        prop_name(WS_CCA_THRESHOLD),
        prop_name(WS_CCA_THRESHOLD_START),
        prop_name(WS_COORD_EXTENDED_ADDRESS),
        prop_name(WS_COORD_SHORT_ADDRESS),
        prop_name(WS_DEFAULT_KEY_SOURCE),
        prop_name(WS_DEVICE_DESCRIPTION_PAN_ID_UPDATE),
        prop_name(WS_DEVICE_STATISTICS),
        prop_name(WS_DEVICE_STATISTICS_CLEAR),
        prop_name(WS_DEVICE_TABLE),
        prop_name(WS_EDFE_FORCE_STOP),
        prop_name(WS_ENABLE_FRAME_COUNTER_PER_KEY),
        prop_name(WS_FHSS_CREATE),
        prop_name(WS_FHSS_DELETE),
        prop_name(WS_FHSS_DROP_NEIGHBOR),
        prop_name(WS_FHSS_REGISTER),
        prop_name(WS_FHSS_SET_CONF),
        prop_name(WS_FHSS_SET_HOP_COUNT),
        prop_name(WS_FHSS_SET_PARENT),
        prop_name(WS_FHSS_SET_TX_ALLOWANCE_LEVEL),
        prop_name(WS_FHSS_UNREGISTER),
        prop_name(WS_FHSS_UPDATE_NEIGHBOR),
        prop_name(WS_FRAME_COUNTER),
        prop_name(WS_GLOBAL_TX_DURATION),
        prop_name(WS_KEY_TABLE),
        prop_name(WS_MAC_FILTER_ADD_LONG),
        prop_name(WS_MAC_FILTER_CLEAR),
        prop_name(WS_MAC_FILTER_START),
        prop_name(WS_MAC_FILTER_STOP),
        prop_name(WS_MAX_BE),
        prop_name(WS_MAX_CSMA_BACKOFFS),
        prop_name(WS_MAX_FRAME_RETRIES),
        prop_name(WS_MCPS_DROP),
        prop_name(WS_MIN_BE),
        prop_name(WS_MLME_IND),
        prop_name(WS_MULTI_CSMA_PARAMETERS),
        prop_name(WS_RCP_CRC_ERR),
        prop_name(WS_REGIONAL_REGULATION),
        prop_name(WS_REQUEST_RESTART),
        prop_name(WS_RESET),
        prop_name(WS_RF_CONFIGURATION_LEGACY),
        prop_name(WS_RF_CONFIGURATION_LIST),
        prop_name(WS_RX_ON_WHEN_IDLE),
        prop_name(WS_RX_SENSITIVITY),
        prop_name(WS_SECURITY_ENABLED),
        prop_name(WS_START),
        prop_name(WS_TX_POWER),
    };

    for (int i = 0; i < ARRAY_SIZE(spinel_props); i++)
        if (prop == spinel_props[i].val)
            return spinel_props[i].str;
    return NULL;
}

bool spinel_prop_is_valid(struct iobuf_read *buf, int prop)
{
    if (buf->err) {
        ERROR("spinel error (offset %d): %s", buf->cnt, spinel_prop_str(prop));
        return false;
    }
    if (iobuf_remaining_size(buf)) {
        ERROR("spinel error (data left): %s", spinel_prop_str(prop));
        return false;
    }
    return true;
}

void spinel_trace(const uint8_t *buf, size_t buf_len, const char *prefix)
{
    struct iobuf_read iobuf = {
        .data_size = buf_len,
        .data = buf,
    };
    unsigned int cmd, prop = -1;
    const char *cmd_str, *prop_str;

    if (!(g_enabled_traces & TR_HIF))
        return;

    iobuf_pop_u8(&iobuf); // ignore header
    cmd = __hif_pop_uint(&iobuf);
    switch (cmd) {
        case SPINEL_CMD_PROP_IS:
        case SPINEL_CMD_PROP_GET:
        case SPINEL_CMD_PROP_SET:
            prop = __hif_pop_uint(&iobuf);
            break;
    }
    cmd_str = spinel_cmd_str(cmd);
    prop_str = spinel_prop_str(prop);
    TRACE(TR_HIF, "%s%s/%s %s (%d bytes)", prefix, cmd_str, prop_str,
          tr_bytes(iobuf_ptr(&iobuf), iobuf_remaining_size(&iobuf),
                   NULL, 128, DELIM_SPACE | ELLIPSIS_STAR),
          iobuf.data_size);
}
