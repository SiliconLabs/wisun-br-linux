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
#include <stdint.h>
#include <string.h>

#include "spinel_buffer.h"
#include "spinel_defs.h"
#include "utils.h"
#include "iobuf.h"
#include "log.h"

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

void spinel_push_bool(struct iobuf_write *buf, bool val)
{
    iobuf_push_u8(buf, val);
    TRACE(TR_HIF_EXTRA, "hif tx:     bool: %s", val ? "true" : "false");
}

void spinel_push_uint(struct iobuf_write *buf, unsigned int val)
{
    TRACE(TR_HIF_EXTRA, "hif tx:     uint: %u", val);
    do {
        iobuf_push_u8(buf, (val & 0x7F) | 0x80);
        val >>= 7;
    } while (val);
    buf->data[buf->len - 1] &= ~0x80;
}

void spinel_push_u8(struct iobuf_write *buf, uint8_t val)
{
    iobuf_push_u8(buf, val);
    TRACE(TR_HIF_EXTRA, "hif tx:       u8: %u", val);
}

void spinel_push_i8(struct iobuf_write *buf, int8_t val)
{
    iobuf_push_u8(buf, (uint8_t)val);
    TRACE(TR_HIF_EXTRA, "hif tx:       i8: %i", val);
}

void spinel_push_fixed_u8_array(struct iobuf_write *buf, const uint8_t *val, int num)
{
    iobuf_push_data(buf, val, num);
    TRACE(TR_HIF_EXTRA, "hif tx:   u8[%2d]: %s", num,
        tr_bytes(buf->data + buf->len - num, num, NULL, 128, DELIM_SPACE | ELLIPSIS_STAR));
}

void spinel_push_u16(struct iobuf_write *buf, uint16_t val)
{
    iobuf_push_le16(buf, val);
    TRACE(TR_HIF_EXTRA, "hif tx:      u16: %u", val);
}

void spinel_push_i16(struct iobuf_write *buf, int16_t val)
{
    iobuf_push_le16(buf, (uint16_t)val);
    TRACE(TR_HIF_EXTRA, "hif tx:      i16: %i", val);
}

void spinel_push_fixed_u16_array(struct iobuf_write *buf, const uint16_t *val, int num)
{
    for (int i = 0; i < num; i++)
        iobuf_push_le16(buf, val[i]);
    TRACE(TR_HIF_EXTRA, "hif tx:  u16[%2d]: %s", num,
        tr_bytes(buf->data + buf->len - 2 * num, 2 * num, NULL, 128, DELIM_SPACE | ELLIPSIS_STAR));
}

void spinel_push_u32(struct iobuf_write *buf, uint32_t val)
{
    iobuf_push_le32(buf, val);
    TRACE(TR_HIF_EXTRA, "hif tx:      u32: %u", val);
}

void spinel_push_i32(struct iobuf_write *buf, int32_t val)
{
    iobuf_push_le32(buf, (uint32_t)val);
    TRACE(TR_HIF_EXTRA, "hif tx:      i32: %i", val);
}

void spinel_push_fixed_u32_array(struct iobuf_write *buf, const uint32_t *val, int num)
{
    for (int i = 0; i < num; i++)
        iobuf_push_le32(buf, val[i]);
    TRACE(TR_HIF_EXTRA, "hif tx:  u32[%2d]: %s", num,
        tr_bytes(buf->data + buf->len - 4 * num, 4 * num, NULL, 128, DELIM_SPACE | ELLIPSIS_STAR));
}

void spinel_push_str(struct iobuf_write *buf, const char *val)
{
    iobuf_push_data(buf, (const uint8_t *)val, strlen(val) + 1);
    TRACE(TR_HIF_EXTRA, "hif tx:   string: %s", val);
}

void spinel_push_data(struct iobuf_write *buf, const uint8_t *val, size_t size)
{
    iobuf_push_le16(buf, size);
    iobuf_push_data(buf, val, size);
    TRACE(TR_HIF_EXTRA, "hif tx:     data: %s (%zu bytes)",
        tr_bytes(val, size, NULL, 128, DELIM_SPACE | ELLIPSIS_STAR), size);
}

void spinel_push_raw(struct iobuf_write *buf, const uint8_t *val, size_t size)
{
    iobuf_push_data(buf, val, size);
    TRACE(TR_HIF_EXTRA, "hif tx:      raw: %s (%zu bytes)",
        tr_bytes(val, size, NULL, 128, DELIM_SPACE | ELLIPSIS_STAR), size);
}

bool spinel_pop_bool(struct iobuf_read *buf)
{
    uint8_t val;

    if (buf->err)
        return false;
    val = iobuf_pop_u8(buf);
    WARN_ON(val != 1 && val != 0);
    if (!buf->err)
        TRACE(TR_HIF_EXTRA, "hif rx:     bool: %s", val ? "true" : "false");
    return val;
}

static unsigned int __spinel_pop_uint(struct iobuf_read *buf)
{
    unsigned int val = 0;
    uint8_t cur;
    int i = 0;

    do {
        cur = iobuf_pop_u8(buf);
        val |= (cur & 0x7F) << i;
        i += 7;
        if (i > 32) {
            buf->err = true;
            return 0;
        }
    } while (cur & 0x80);
    return val;
}

unsigned int spinel_pop_uint(struct iobuf_read *buf)
{
    unsigned int val = __spinel_pop_uint(buf);

    if (!buf->err)
        TRACE(TR_HIF_EXTRA, "hif rx:     uint: %u", val);
    return val;
}

uint8_t spinel_pop_u8(struct iobuf_read *buf) {
    uint8_t val = iobuf_pop_u8(buf);

    if (!buf->err)
        TRACE(TR_HIF_EXTRA, "hif rx:       u8: %u", val);
    return val;
}

int8_t spinel_pop_i8(struct iobuf_read *buf)
{
    int8_t val = iobuf_pop_u8(buf);

    if (!buf->err)
        TRACE(TR_HIF_EXTRA, "hif rx:       i8: %i", val);
    return val;
}

void spinel_pop_fixed_u8_array(struct iobuf_read *buf, uint8_t *val, int num)
{
    iobuf_pop_data(buf, val, num);
    if (!buf->err)
        TRACE(TR_HIF_EXTRA, "hif rx:   u8[%2d]: %s", num,
            tr_bytes(iobuf_ptr(buf) - num, num, NULL, 128, DELIM_SPACE | ELLIPSIS_STAR));
}

uint16_t spinel_pop_u16(struct iobuf_read *buf)
{
    uint16_t val = iobuf_pop_le16(buf);

    if (!buf->err)
        TRACE(TR_HIF_EXTRA, "hif rx:      u16: %u", val);
    return val;
}

int16_t spinel_pop_i16(struct iobuf_read *buf)
{
    int16_t val = iobuf_pop_le16(buf);

    if (!buf->err)
        TRACE(TR_HIF_EXTRA, "hif rx:      i16: %i", val);
    return val;
}

void spinel_pop_fixed_u16_array(struct iobuf_read *buf, uint16_t *val, int num)
{
    for (int i = 0; i < num; i++)
        val[i] = iobuf_pop_le16(buf);
    if (!buf->err)
        TRACE(TR_HIF_EXTRA, "hif rx:  u16[%2d]: %s", num,
            tr_bytes(iobuf_ptr(buf) - 2 * num, 2 * num, NULL, 128, DELIM_SPACE | ELLIPSIS_STAR));
}

uint32_t spinel_pop_u32(struct iobuf_read *buf)
{
    uint32_t val = iobuf_pop_le32(buf);

    if (!buf->err)
        TRACE(TR_HIF_EXTRA, "hif rx:      u32: %u", val);
    return val;
}

int32_t spinel_pop_i32(struct iobuf_read *buf)
{
    int32_t val = iobuf_pop_le32(buf);

    if (!buf->err)
        TRACE(TR_HIF_EXTRA, "hif rx:      i32: %i", val);
    return val;
}

void spinel_pop_fixed_u32_array(struct iobuf_read *buf, uint32_t *val, int num)
{
    for (int i = 0; i < num; i++)
        val[i] = iobuf_pop_le32(buf);
    if (!buf->err)
        TRACE(TR_HIF_EXTRA, "hif rx:  u32[%2d]: %s", num,
            tr_bytes(iobuf_ptr(buf) - 4 * num, 4 * num, NULL, 128, DELIM_SPACE | ELLIPSIS_STAR));
}

const char *spinel_pop_str(struct iobuf_read *buf)
{
    const char *val = (char *)iobuf_ptr(buf);
    int len = strnlen(val, iobuf_remaining_size(buf));

    if (len == iobuf_remaining_size(buf) && val[len - 1]) {
        buf->err = true;
        return NULL;
    }
    buf->cnt += len + 1;
    if (!buf->err)
        TRACE(TR_HIF_EXTRA, "hif rx:   string: %s", val);
    return val;
}

unsigned int spinel_pop_data_ptr(struct iobuf_read *buf, const uint8_t **val)
{
    const uint8_t *ptr;
    unsigned int size = iobuf_pop_le16(buf);

    ptr = iobuf_pop_data_ptr(buf, size);
    if (val)
        *val = ptr;
    if (!buf->err)
        TRACE(TR_HIF_EXTRA, "hif rx:     data: %s (%u bytes)",
            size ? tr_bytes(ptr, size, NULL, 128, DELIM_SPACE | ELLIPSIS_STAR) : "-", size);
    return size;
}

unsigned int spinel_pop_data(struct iobuf_read *buf, uint8_t *val, unsigned int val_size)
{
    const uint8_t *ptr;
    unsigned int size;

    size = iobuf_pop_le16(buf);
    WARN_ON(size > val_size, "hif rx: data bigger than buffer");
    ptr = iobuf_pop_data_ptr(buf, size);
    if (val)
        memcpy(val, ptr, MIN(size, val_size));
    if (!buf->err)
        TRACE(TR_HIF_EXTRA, "hif rx:     data: %s (%u bytes)",
            size ? tr_bytes(ptr, size, NULL, 128, DELIM_SPACE | ELLIPSIS_STAR) : "-", size);
    return size;
}

unsigned int spinel_pop_raw_ptr(struct iobuf_read *buf, const uint8_t **val)
{
    unsigned int size = iobuf_remaining_size(buf);

    *val = iobuf_pop_data_ptr(buf, size);
    if (!buf->err)
        TRACE(TR_HIF_EXTRA, "hif rx:      raw: %s (%u bytes)",
            size ? tr_bytes(*val, size, NULL, 128, DELIM_SPACE | ELLIPSIS_STAR) : "-", size);
    return size;
}

unsigned int spinel_pop_raw(struct iobuf_read *buf, uint8_t *val, unsigned int val_size)
{
    unsigned int size = MIN(iobuf_remaining_size(buf), val_size);

    iobuf_pop_data(buf, val, size);
    if (!buf->err)
        TRACE(TR_HIF_EXTRA, "hif rx:      raw: %s (%u bytes)",
            size ? tr_bytes(val, size, NULL, 128, DELIM_SPACE | ELLIPSIS_STAR) : "-", size);
    return size;
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

static void spinel_trace(struct iobuf_read *buf, const char *prefix)
{
    unsigned int cmd, prop = -1;
    const char *cmd_str, *prop_str;

    if (!(g_enabled_traces & TR_HIF))
        return;

    iobuf_pop_u8(buf); // ignore header
    cmd = __spinel_pop_uint(buf);
    switch (cmd) {
        case SPINEL_CMD_PROP_IS:
        case SPINEL_CMD_PROP_GET:
        case SPINEL_CMD_PROP_SET:
            prop = __spinel_pop_uint(buf);
            break;
    }
    cmd_str = spinel_cmd_str(cmd);
    prop_str = spinel_prop_str(prop);
    TRACE(TR_HIF, "%s%s/%s %s (%d bytes)", prefix, cmd_str, prop_str,
          tr_bytes(iobuf_ptr(buf), iobuf_remaining_size(buf),
                   NULL, 128, DELIM_SPACE | ELLIPSIS_STAR),
          buf->data_size);
}

void spinel_trace_tx(struct iobuf_write *buf)
{
    struct iobuf_read tr_buf = {
        .data_size = buf->len,
        .data = buf->data,
    };

    spinel_trace(&tr_buf, "hif tx: ");
}

void spinel_trace_rx(struct iobuf_read *buf)
{
    struct iobuf_read tr_buf = {
        .data_size = buf->data_size,
        .data = buf->data,
    };

    spinel_trace(&tr_buf, "hif rx: ");
}
