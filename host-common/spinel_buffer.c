#include <stdint.h>
#include <string.h>

#include "spinel_buffer.h"
#include "spinel.h"
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
    BUG_ON(ret < 0);
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
