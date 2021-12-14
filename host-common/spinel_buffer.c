#include <stdint.h>
#include <string.h>

#include "spinel_buffer.h"
#include "spinel.h"
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
    int ret;

    BUG_ON(buf->cnt + 1 > buf->len);
    ret = spinel_datatype_pack(buf->frame + buf->cnt, buf->len - buf->cnt, "b", val);
    BUG_ON(ret != 1);
    buf->cnt += ret;
}

void spinel_push_int(struct spinel_buffer *buf, int val)
{
    int ret;

    BUG_ON(buf->cnt + 3 > buf->len);
    ret = spinel_datatype_pack(buf->frame + buf->cnt, buf->len - buf->cnt, "i", val);
    BUG_ON(ret < 1 || ret > 3);
    buf->cnt += ret;
}

void spinel_push_u8(struct spinel_buffer *buf, uint8_t val)
{
    int ret;

    BUG_ON(buf->cnt + 1 > buf->len);
    ret = spinel_datatype_pack(buf->frame + buf->cnt, buf->len - buf->cnt, "C", val);
    BUG_ON(ret != 1);
    buf->cnt += ret;
}

void spinel_push_u16(struct spinel_buffer *buf, uint16_t val)
{
    int ret;

    BUG_ON(buf->cnt + 2 > buf->len);
    ret = spinel_datatype_pack(buf->frame + buf->cnt, buf->len - buf->cnt, "S", val);
    BUG_ON(ret != 2);
    buf->cnt += ret;
}

void spinel_push_u32(struct spinel_buffer *buf, uint32_t val)
{
    int ret;

    BUG_ON(buf->cnt + 4 > buf->len);
    ret = spinel_datatype_pack(buf->frame + buf->cnt, buf->len - buf->cnt, "L", val);
    BUG_ON(ret != 4);
    buf->cnt += ret;
}

void spinel_push_i8(struct spinel_buffer *buf, int8_t val)
{
    int ret;

    BUG_ON(buf->cnt + 1 > buf->len);
    ret = spinel_datatype_pack(buf->frame + buf->cnt, buf->len - buf->cnt, "c", val);
    BUG_ON(ret != 1);
    buf->cnt += ret;
}

void spinel_push_i16(struct spinel_buffer *buf, int16_t val)
{
    int ret;

    BUG_ON(buf->cnt + 2 > buf->len);
    ret = spinel_datatype_pack(buf->frame + buf->cnt, buf->len - buf->cnt, "s", val);
    BUG_ON(ret != 2);
    buf->cnt += ret;
}

void spinel_push_i32(struct spinel_buffer *buf, int32_t val)
{
    int ret;

    BUG_ON(buf->cnt + 4 > buf->len);
    ret = spinel_datatype_pack(buf->frame + buf->cnt, buf->len - buf->cnt, "l", val);
    BUG_ON(ret != 4);
    buf->cnt += ret;
}

void spinel_push_str(struct spinel_buffer *buf, const char *val)
{
    int ret;

    BUG_ON(buf->cnt + (int)strlen(val) + 1 > buf->len);
    ret = spinel_datatype_pack(buf->frame + buf->cnt, buf->len - buf->cnt, "U", val);
    BUG_ON(ret != (int)strlen(val) + 1);
    buf->cnt += ret;
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
    int ret;

    BUG_ON(buf->cnt + size + 2 > buf->len);
    ret = spinel_datatype_pack(buf->frame + buf->cnt, buf->len - buf->cnt, "d", val, size);
    BUG_ON(ret != size + 2);
    buf->cnt += ret;
}

void spinel_push_raw(struct spinel_buffer *buf, const uint8_t *val, size_t size)
{
    int ret;

    BUG_ON(buf->cnt + size > buf->len);
    ret = spinel_datatype_pack(buf->frame + buf->cnt, buf->len - buf->cnt, "D", val, size);
    BUG_ON(ret != size);
    buf->cnt += ret;
}

bool spinel_pop_bool(struct spinel_buffer *buf)
{
    uint8_t val;
    int ret;

    BUG_ON(buf->cnt + 1 > buf->len);
    ret = spinel_datatype_unpack(buf->frame + buf->cnt, buf->len - buf->cnt, "b", &val);
    BUG_ON(ret != 1);
    WARN_ON(val != 1 && val != 0);
    buf->cnt += ret;
    return val;
}

int spinel_pop_int(struct spinel_buffer *buf)
{
    int val;
    int ret;

    BUG_ON(buf->cnt + 1 > buf->len);
    ret = spinel_datatype_unpack(buf->frame + buf->cnt, buf->len - buf->cnt, "i", &val);
    BUG_ON(ret < 1 || ret > 3, "%d %d %d", ret, buf->cnt, buf->len);
    buf->cnt += ret;
    return val;
}

uint8_t spinel_pop_u8(struct spinel_buffer *buf)
{
    uint8_t val;
    int ret;

    BUG_ON(buf->cnt + 1 > buf->len);
    ret = spinel_datatype_unpack(buf->frame + buf->cnt, buf->len - buf->cnt, "C", &val);
    BUG_ON(ret != 1);
    buf->cnt += ret;
    return val;
}

uint16_t spinel_pop_u16(struct spinel_buffer *buf)
{
    uint16_t val;
    int ret;

    BUG_ON(buf->cnt + 2 > buf->len);
    ret = spinel_datatype_unpack(buf->frame + buf->cnt, buf->len - buf->cnt, "S", &val);
    BUG_ON(ret != 2);
    buf->cnt += ret;
    return val;
}

uint32_t spinel_pop_u32(struct spinel_buffer *buf)
{
    uint32_t val;
    int ret;

    BUG_ON(buf->cnt + 4 > buf->len);
    ret = spinel_datatype_unpack(buf->frame + buf->cnt, buf->len - buf->cnt, "L", &val);
    BUG_ON(ret != 4);
    buf->cnt += ret;
    return val;
}

int8_t spinel_pop_i8(struct spinel_buffer *buf)
{
    int8_t val;
    int ret;

    BUG_ON(buf->cnt + 1 > buf->len);
    ret = spinel_datatype_unpack(buf->frame + buf->cnt, buf->len - buf->cnt, "c", &val);
    BUG_ON(ret != 1);
    buf->cnt += ret;
    return val;
}

int16_t spinel_pop_i16(struct spinel_buffer *buf)
{
    int16_t val;
    int ret;

    BUG_ON(buf->cnt + 2 > buf->len);
    ret = spinel_datatype_unpack(buf->frame + buf->cnt, buf->len - buf->cnt, "s", &val);
    BUG_ON(ret != 2);
    buf->cnt += ret;
    return val;
}

int32_t spinel_pop_i32(struct spinel_buffer *buf)
{
    int32_t val;
    int ret;

    BUG_ON(buf->cnt + 4 > buf->len);
    ret = spinel_datatype_unpack(buf->frame + buf->cnt, buf->len - buf->cnt, "l", &val);
    BUG_ON(ret != 4);
    buf->cnt += ret;
    return val;
}

const char *spinel_pop_str(struct spinel_buffer *buf)
{
    const char *val;
    int ret;

    ret = spinel_datatype_unpack(buf->frame + buf->cnt, buf->len - buf->cnt, "U", &val);
    BUG_ON(ret != (int)strlen(val) + 1);
    buf->cnt += ret;
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

unsigned int spinel_pop_data(struct spinel_buffer *buf, uint8_t *val, unsigned int size)
{
    int ret;

    ret = spinel_datatype_unpack_in_place(buf->frame + buf->cnt, buf->len - buf->cnt, "d", val, &size);
    BUG_ON(ret < 2);
    BUG_ON(ret != size + 2);
    buf->cnt += ret;
    return size;
}

unsigned int spinel_pop_data_ptr(struct spinel_buffer *buf, uint8_t **val)
{
    unsigned int size = -1;
    int ret;

    ret = spinel_datatype_unpack(buf->frame + buf->cnt, buf->len - buf->cnt, "d", val, &size);
    BUG_ON(ret < 0);
    BUG_ON(ret != size + 2);
    buf->cnt += ret;
    return size;
}

unsigned int spinel_pop_raw(struct spinel_buffer *buf, uint8_t *val, unsigned int size, bool check_exact_size)
{
    unsigned int true_size = size;
    int ret;

    if (size >= spinel_remaining_size(buf)) {
        ret = spinel_datatype_unpack_in_place(buf->frame + buf->cnt, buf->len - buf->cnt, "D", val, &true_size);
    } else {
        // There is no way to make that with spinel_datatype_unpack_in_place()
        memcpy(val, buf->frame + buf->cnt, size);
        ret = size;
    }
    BUG_ON(ret < 0);
    BUG_ON(ret != true_size);
    if (check_exact_size)
        BUG_ON(true_size != size);
    buf->cnt += ret;
    return size;
}

unsigned int spinel_pop_raw_ptr(struct spinel_buffer *buf, uint8_t **val, unsigned int size, bool check_exact_size)
{
    unsigned int true_size = -1;
    int ret;

    BUG_ON(check_exact_size && size < 0);
    ret = spinel_datatype_unpack(buf->frame + buf->cnt, buf->len - buf->cnt, "D", val, &true_size);
    BUG_ON(ret < 0);
    BUG_ON(ret != true_size);
    if (check_exact_size)
        BUG_ON(true_size != size);
    buf->cnt += ret;
    return size;
}

static const struct {
    char *str;
    int val;
} spinel_cmds[] = {
    { "PROP_IS",  SPINEL_CMD_PROP_VALUE_IS },
    { "PROP_SET", SPINEL_CMD_PROP_VALUE_SET },
    { "PROP_GET", SPINEL_CMD_PROP_VALUE_GET },
    { "NOOP",     SPINEL_CMD_NOOP },
    { "RESET",    SPINEL_CMD_RESET },
};

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

void spinel_trace(const uint8_t *buf, int len, const char *prefix)
{
    static char trace_buffer[128];
    int cmd, prop = -1;
    const char *cmd_str, *prop_str;
    uint8_t hdr;
    int cnt = 0;
    int ret, i;

    ret = spinel_datatype_unpack(buf + cnt, len - cnt, "Ci", &hdr, &cmd);
    if (ret < 0) {
        WARN("malformed spinel_buffer");
        return;
    }
    cnt += ret;
    switch (cmd) {
        case SPINEL_CMD_PROP_VALUE_IS:
        case SPINEL_CMD_PROP_VALUE_GET:
        case SPINEL_CMD_PROP_VALUE_SET:
            ret = spinel_datatype_unpack(buf + cnt, len - cnt, "i", &prop);
            if (ret < 0) {
                WARN("malformed spinel_buffer");
                return;
            }
            cnt += ret;
            break;
    }
    cmd_str = NULL;
    for (i = 0; i < ARRAY_SIZE(spinel_cmds); i++)
        if (cmd == spinel_cmds[i].val)
            cmd_str = spinel_cmds[i].str;
    prop_str = NULL;
    for (i = 0; i < ARRAY_SIZE(spinel_props); i++)
        if (prop == spinel_props[i].val)
            prop_str = spinel_props[i].str;
    TRACE(TR_HIF, "%s%s/%s %s (%d bytes)", prefix, cmd_str, prop_str,
           bytes_str(buf + cnt, len - cnt, NULL, trace_buffer, sizeof(trace_buffer), DELIM_SPACE | ELLIPSIS_STAR), len);
}
