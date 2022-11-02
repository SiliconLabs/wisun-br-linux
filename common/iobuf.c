/*
 * Copyright (c) 2022 Silicon Laboratories Inc. (www.silabs.com)
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

#include <stdlib.h>
#include <string.h>
#include "common/utils.h"
#include "common/log.h"
#include "iobuf.h"

static void iobuf_enlarge_buffer(struct iobuf_write *buf, size_t new_data_size) {
    if (buf->data_size < buf->len + new_data_size) {
        buf->data_size = max(64, buf->len + new_data_size);
        buf->data = realloc(buf->data, buf->data_size);
        BUG_ON(!buf->data);
    }
}

void iobuf_push_u8(struct iobuf_write *buf, uint16_t val) {
    iobuf_enlarge_buffer(buf, 1);
    buf->data[buf->len + 0] = val;
    buf->len += 1;
}

void iobuf_push_be16(struct iobuf_write *buf, uint16_t val) {
    iobuf_enlarge_buffer(buf, 2);
    buf->data[buf->len + 0] = val >> 8;
    buf->data[buf->len + 1] = val >> 0;
    buf->len += 2;
}

void iobuf_push_le16(struct iobuf_write *buf, uint16_t val) {
    iobuf_enlarge_buffer(buf, 2);
    buf->data[buf->len + 0] = val >> 0;
    buf->data[buf->len + 1] = val >> 8;
    buf->len += 2;
}

void iobuf_push_be24(struct iobuf_write *buf, uint24_t val) {
    iobuf_enlarge_buffer(buf, 3);
    buf->data[buf->len + 0] = val >> 16;
    buf->data[buf->len + 1] = val >> 8;
    buf->data[buf->len + 2] = val >> 0;
    buf->len += 3;
}

void iobuf_push_le24(struct iobuf_write *buf, uint24_t val) {
    iobuf_enlarge_buffer(buf, 3);
    buf->data[buf->len + 0] = val >> 0;
    buf->data[buf->len + 1] = val >> 8;
    buf->data[buf->len + 2] = val >> 16;
    buf->len += 3;
}

void iobuf_push_be32(struct iobuf_write *buf, uint32_t val) {
    iobuf_enlarge_buffer(buf, 4);
    buf->data[buf->len + 0] = val >> 24;
    buf->data[buf->len + 1] = val >> 16;
    buf->data[buf->len + 2] = val >> 8;
    buf->data[buf->len + 3] = val >> 0;
    buf->len += 4;
}

void iobuf_push_le32(struct iobuf_write *buf, uint32_t val) {
    iobuf_enlarge_buffer(buf, 4);
    buf->data[buf->len + 0] = val >> 0;
    buf->data[buf->len + 1] = val >> 8;
    buf->data[buf->len + 2] = val >> 16;
    buf->data[buf->len + 3] = val >> 24;
    buf->len += 4;
}

void iobuf_push_data(struct iobuf_write *buf, const uint8_t *val, int num)
{
    iobuf_enlarge_buffer(buf, num);
    memcpy(buf->data + buf->len, val, num);
    buf->len += num;
}

void iobuf_free(struct iobuf_write *buf) {
    free(buf->data);
}

static bool iobuf_validate(struct iobuf_read *buf, size_t data_size)
{
    if (buf->err || iobuf_remaining_size(buf) < data_size) {
        buf->cnt = buf->data_size;
        buf->err = true;
        return false;
    }
    return true;
}

int iobuf_remaining_size(const struct iobuf_read *buf)
{
    return buf->data_size - buf->cnt;
}

const uint8_t *iobuf_ptr(const struct iobuf_read *buf)
{
    return buf->data + buf->cnt;
}

uint8_t iobuf_pop_u8(struct iobuf_read *buf) {
    uint8_t val;

    if (!iobuf_validate(buf, 1))
        return 0;
    val = buf->data[buf->cnt];
    buf->cnt += 1;
    return val;
}

uint16_t iobuf_pop_be16(struct iobuf_read *buf) {
    uint16_t val = 0;

    if (!iobuf_validate(buf, 2))
        return 0;
    val = buf->data[buf->cnt + 0] << 8;
    val |= buf->data[buf->cnt + 1] << 0;
    buf->cnt += 2;
    return val;
}

uint16_t iobuf_pop_le16(struct iobuf_read *buf) {
    uint16_t val = 0;

    if (!iobuf_validate(buf, 2))
        return 0;
    val = buf->data[buf->cnt + 0] << 0;
    val |= buf->data[buf->cnt + 1] << 8;
    buf->cnt += 2;
    return val;
}

uint24_t iobuf_pop_be24(struct iobuf_read *buf) {
    uint24_t val = 0;

    if (!iobuf_validate(buf, 3))
        return 0;
    val |= buf->data[buf->cnt + 0] << 16;
    val |= buf->data[buf->cnt + 1] << 8;
    val |= buf->data[buf->cnt + 2] << 0;
    buf->cnt += 3;
    return val;
}

uint24_t iobuf_pop_le24(struct iobuf_read *buf) {
    uint24_t val = 0;

    if (!iobuf_validate(buf, 3))
        return 0;
    val |= buf->data[buf->cnt + 0] << 0;
    val |= buf->data[buf->cnt + 1] << 8;
    val |= buf->data[buf->cnt + 2] << 16;
    buf->cnt += 3;
    return val;
}

uint32_t iobuf_pop_be32(struct iobuf_read *buf) {
    uint32_t val = 0;

    if (!iobuf_validate(buf, 4))
        return 0;
    val |= buf->data[buf->cnt + 0] << 24;
    val |= buf->data[buf->cnt + 1] << 16;
    val |= buf->data[buf->cnt + 2] << 8;
    val |= buf->data[buf->cnt + 3] << 0;
    buf->cnt += 4;
    return val;
}

uint32_t iobuf_pop_le32(struct iobuf_read *buf) {
    uint32_t val = 0;

    if (!iobuf_validate(buf, 4))
        return 0;
    val |= buf->data[buf->cnt + 0] << 0;
    val |= buf->data[buf->cnt + 1] << 8;
    val |= buf->data[buf->cnt + 2] << 16;
    val |= buf->data[buf->cnt + 3] << 24;
    buf->cnt += 4;
    return val;
}

void iobuf_pop_data(struct iobuf_read *buf, uint8_t *val, size_t size)
{
    if (!iobuf_validate(buf, size)) {
        memset(val, 0, size);
        return;
    }
    memcpy(val, buf->data + buf->cnt, size);
    buf->cnt += size;
}

const uint8_t *iobuf_pop_data_ptr(struct iobuf_read *buf, size_t size)
{
    const uint8_t *val;

    if (!iobuf_validate(buf, size))
        return NULL;
    val = buf->data + buf->cnt;
    buf->cnt += size;
    return val;
}
