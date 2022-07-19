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
#include <stdint.h>
#include <string.h>

#include "spinel_buffer.h"
#include "spinel_defs.h"
#include "utils.h"
#include "log.h"

int spinel_remaining_size(const struct spinel_buffer *buf)
{
    return buf->len - buf->cnt;
}

uint8_t *spinel_ptr(struct spinel_buffer *buf)
{
    return buf->frame + buf->cnt;
}

void spinel_reset(struct spinel_buffer *buf)
{
    buf->cnt = 0;
}

void spinel_push_bool(struct spinel_buffer *buf, bool val)
{
    buf->frame[buf->cnt + 0] = val;
    buf->cnt += 1;
    BUG_ON(buf->cnt > buf->len);
}

static int spinel_encode_uint(uint8_t *buf, unsigned int val)
{
    int cnt = 0;

    do {
        buf[cnt++] = (val & 0x7F) | 0x80;
        val >>= 7;
    } while(val);
    buf[cnt - 1] &= ~0x80;
    return cnt;
}

// FIXME: replace by
// void spinel_push_uint(struct spinel_buffer *buf, unsigned int val)
void spinel_push_uint(struct spinel_buffer *buf, unsigned int val)
{
    buf->cnt += spinel_encode_uint(buf->frame + buf->cnt, val);
    BUG_ON(buf->cnt > buf->len);
}

void spinel_push_u8(struct spinel_buffer *buf, uint8_t val)
{
    buf->frame[buf->cnt] = val;
    buf->cnt += 1;
    BUG_ON(buf->cnt > buf->len);
}

void spinel_push_u16(struct spinel_buffer *buf, uint16_t val)
{
    buf->frame[buf->cnt + 0] = val >> 0;
    buf->frame[buf->cnt + 1] = val >> 8;
    buf->cnt += 2;
    BUG_ON(buf->cnt > buf->len);
}

void spinel_push_u32(struct spinel_buffer *buf, uint32_t val)
{
    buf->frame[buf->cnt + 0] = val >> 0;
    buf->frame[buf->cnt + 1] = val >> 8;
    buf->frame[buf->cnt + 2] = val >> 16;
    buf->frame[buf->cnt + 3] = val >> 24;
    buf->cnt += 4;
    BUG_ON(buf->cnt > buf->len);
}

void spinel_push_i8(struct spinel_buffer *buf, int8_t val)
{
    spinel_push_u8(buf, (uint8_t)val);
}

void spinel_push_i16(struct spinel_buffer *buf, int16_t val)
{
    spinel_push_u16(buf, (uint16_t)val);
}

void spinel_push_i32(struct spinel_buffer *buf, int32_t val)
{
    spinel_push_u32(buf, (uint32_t)val);
}

void spinel_push_str(struct spinel_buffer *buf, const char *val)
{
    int size = strlen(val) + 1; // include final '\0'

    memcpy(buf->frame + buf->cnt, val, size);
    buf->cnt += size;
    BUG_ON(buf->cnt > buf->len);
}

void spinel_push_fixed_u8_array(struct spinel_buffer *buf, const uint8_t *val, int num)
{
    int i;

    for (i = 0; i < num; i++)
        spinel_push_u8(buf, val[i]);
}

void spinel_push_fixed_u16_array(struct spinel_buffer *buf, const uint16_t *val, int num)
{
    int i;

    for (i = 0; i < num; i++)
        spinel_push_u16(buf, val[i]);
}

void spinel_push_fixed_u32_array(struct spinel_buffer *buf, const uint32_t *val, int num)
{
    int i;

    for (i = 0; i < num; i++)
        spinel_push_u32(buf, val[i]);
}

void spinel_push_data(struct spinel_buffer *buf, const uint8_t *val, size_t size)
{
    spinel_push_u16(buf, size);
    memcpy(buf->frame + buf->cnt, val, size);
    buf->cnt += size;
    BUG_ON(buf->cnt > buf->len);
}

void spinel_push_raw(struct spinel_buffer *buf, const uint8_t *val, size_t size)
{
    memcpy(buf->frame + buf->cnt, val, size);
    buf->cnt += size;
    BUG_ON(buf->cnt > buf->len);
}

static bool spinel_pop_is_valid(struct spinel_buffer *buf, int size)
{
    if (spinel_remaining_size(buf) < size)
        buf->err = true;
    return !buf->err;
}

bool spinel_pop_bool(struct spinel_buffer *buf)
{
    uint8_t val;

    if (!spinel_pop_is_valid(buf, 1))
        return false;
    val = buf->frame[buf->cnt];
    WARN_ON(val != 1 && val != 0);
    buf->cnt += 1;
    BUG_ON(buf->cnt > buf->len);
    return val;
}

unsigned int spinel_pop_uint(struct spinel_buffer *buf)
{
    unsigned int val = 0;
    int i = 0;

    do {
        if (!spinel_pop_is_valid(buf, 1))
            return 0;
        val |= (buf->frame[buf->cnt] & 0x7F) << i;
        i += 7;
        if (i > 32) {
            buf->err = true;
            return 0;
        }
    } while (buf->frame[buf->cnt++] & 0x80);
    BUG_ON(buf->cnt > buf->len);
    return val;
}

uint8_t spinel_pop_u8(struct spinel_buffer *buf)
{
    uint8_t val;

    if (!spinel_pop_is_valid(buf, 1))
        return 0;
    val = buf->frame[buf->cnt];
    buf->cnt += 1;
    BUG_ON(buf->cnt > buf->len);
    return val;
}

uint16_t spinel_pop_u16(struct spinel_buffer *buf)
{
    uint16_t val = 0;

    if (!spinel_pop_is_valid(buf, 2))
        return 0;
    val |= buf->frame[buf->cnt + 0] << 0;
    val |= buf->frame[buf->cnt + 1] << 8;
    buf->cnt += 2;
    BUG_ON(buf->cnt > buf->len);
    return val;
}

uint32_t spinel_pop_u32(struct spinel_buffer *buf)
{
    uint32_t val = 0;

    if (!spinel_pop_is_valid(buf, 4))
        return 0;
    val |= buf->frame[buf->cnt + 0] << 0;
    val |= buf->frame[buf->cnt + 1] << 8;
    val |= buf->frame[buf->cnt + 2] << 16;
    val |= buf->frame[buf->cnt + 3] << 24;
    buf->cnt += 4;
    BUG_ON(buf->cnt > buf->len);
    return val;
}

int8_t spinel_pop_i8(struct spinel_buffer *buf)
{
    return (int8_t)spinel_pop_u8(buf);
}

int16_t spinel_pop_i16(struct spinel_buffer *buf)
{
    return (int16_t)spinel_pop_u16(buf);
}

int32_t spinel_pop_i32(struct spinel_buffer *buf)
{
    return (int32_t)spinel_pop_u32(buf);
}

const char *spinel_pop_str(struct spinel_buffer *buf)
{
    const char *val;

    val = (char *)buf->frame + buf->cnt;
    buf->cnt += strnlen(val, spinel_remaining_size(buf)) + 1;
    if (buf->cnt > buf->len) {
        buf->err = true;
        return NULL;
    }
    return val;
}

void spinel_pop_fixed_u8_array(struct spinel_buffer *buf, uint8_t *val, int num)
{
    int i;

    for (i = 0; i < num; i++)
        val[i] = spinel_pop_u8(buf);
}

void spinel_pop_fixed_u16_array(struct spinel_buffer *buf, uint16_t *val, int num)
{
    int i;

    for (i = 0; i < num; i++)
        val[i] = spinel_pop_u16(buf);
}

void spinel_pop_fixed_u32_array(struct spinel_buffer *buf, uint32_t *val, int num)
{
    int i;

    for (i = 0; i < num; i++)
        val[i] = spinel_pop_u32(buf);
}

unsigned int spinel_pop_data(struct spinel_buffer *buf, uint8_t *val, unsigned int val_size)
{
    unsigned int size;

    size = spinel_pop_u16(buf);
    if (!spinel_pop_is_valid(buf, size))
        return 0;
    BUG_ON(size > val_size);
    memcpy(val, buf->frame + buf->cnt, size);
    buf->cnt += size;
    BUG_ON(buf->cnt > buf->len);
    return size;
}

unsigned int spinel_pop_data_ptr(struct spinel_buffer *buf, uint8_t **val)
{
    unsigned int size;

    size = spinel_pop_u16(buf);
    if (!spinel_pop_is_valid(buf, size))
        return 0;
    *val = buf->frame + buf->cnt;
    buf->cnt += size;
    BUG_ON(buf->cnt > buf->len);
    return size;
}

unsigned int spinel_pop_raw(struct spinel_buffer *buf, uint8_t *val, unsigned int val_size, bool check_exact_size)
{
    unsigned int size = spinel_remaining_size(buf);

    if (check_exact_size)
        BUG_ON(size < val_size);
    if (size > val_size)
        size = val_size;
    memcpy(val, buf->frame + buf->cnt, size);
    buf->cnt += size;
    BUG_ON(buf->cnt > buf->len);
    return size;
}

unsigned int spinel_pop_raw_ptr(struct spinel_buffer *buf, uint8_t **val, unsigned int val_size, bool check_exact_size)
{
    unsigned int size = spinel_remaining_size(buf);

    BUG_ON(check_exact_size != !!(val_size > 0));
    if (check_exact_size)
        BUG_ON(size < val_size);
    *val = buf->frame + buf->cnt;
    buf->cnt += size;
    BUG_ON(buf->cnt > buf->len);
    return size;
}

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
    cmd_name(REPLAY_TUN),
};

const char *spinel_cmd_str(int cmd)
{
    for (int i = 0; i < ARRAY_SIZE(spinel_cmds); i++)
        if (cmd == spinel_cmds[i].val)
            return spinel_cmds[i].str;
    return NULL;
}

#define prop_name(name) { #name, SPINEL_PROP_##name }
static const struct {
    char *str;
    int val;
} spinel_props[] = {
    { "-", -1 },
    prop_name(HWADDR),
    prop_name(LAST_STATUS),
    prop_name(MAC_15_4_PANID),
    prop_name(MAC_15_4_SADDR),
    prop_name(PHY_CHAN),
    prop_name(PHY_TX_POWER),
    prop_name(STREAM_RAW),
    prop_name(STREAM_STATUS),
    prop_name(WS_15_4_MODE),
    prop_name(WS_ACCEPT_BYPASS_UNKNOW_DEVICE),
    prop_name(WS_ACK_WAIT_DURATION),
    prop_name(WS_ASSOCIATION_PERMIT),
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
    prop_name(WS_KEY_TABLE),
    prop_name(WS_MAX_BE),
    prop_name(WS_MAX_CSMA_BACKOFFS),
    prop_name(WS_MAX_FRAME_RETRIES),
    prop_name(WS_MIN_BE),
    prop_name(WS_MLME_IND),
    prop_name(WS_MULTI_CSMA_PARAMETERS),
    prop_name(WS_REQUEST_RESTART),
    prop_name(WS_RESET),
    prop_name(WS_RF_CONFIGURATION),
    prop_name(WS_RX_ON_WHEN_IDLE),
    prop_name(WS_SECURITY_ENABLED),
    prop_name(WS_START),
    prop_name(WS_MAC_FILTER_START),
    prop_name(WS_MAC_FILTER_CLEAR),
    prop_name(WS_MAC_FILTER_ADD_LONG),
    prop_name(WS_MAC_FILTER_STOP)
};

const char *spinel_prop_str(int prop)
{
    for (int i = 0; i < ARRAY_SIZE(spinel_props); i++)
        if (prop == spinel_props[i].val)
            return spinel_props[i].str;
    return NULL;
}

bool spinel_prop_is_valid(struct spinel_buffer *buf, int prop)
{
    if (buf->err) {
        ERROR("spinel error (offset %d): %s", buf->cnt, spinel_prop_str(prop));
        return false;
    }
    if (spinel_remaining_size(buf)) {
        ERROR("spinel error (data left): %s", spinel_prop_str(prop));
        return false;
    }
    return true;
}

void spinel_trace(struct spinel_buffer *buf, const char *prefix)
{
    unsigned int cmd, prop = -1;
    const char *cmd_str, *prop_str;
    int cnt_bkp = buf->cnt;

    if (!(g_enabled_traces & TR_HIF))
        return;

    spinel_reset(buf);
    spinel_pop_u8(buf); // ignore header
    cmd = spinel_pop_uint(buf);
    switch (cmd) {
        case SPINEL_CMD_PROP_IS:
        case SPINEL_CMD_PROP_GET:
        case SPINEL_CMD_PROP_SET:
            prop = spinel_pop_uint(buf);
            break;
    }
    cmd_str = spinel_cmd_str(cmd);
    prop_str = spinel_prop_str(prop);
    TRACE(TR_HIF, "%s%s/%s %s (%d bytes)", prefix, cmd_str, prop_str,
          tr_bytes(spinel_ptr(buf), spinel_remaining_size(buf), NULL, 128, DELIM_SPACE | ELLIPSIS_STAR), buf->len);
    buf->cnt = cnt_bkp; // reset buffer
}
