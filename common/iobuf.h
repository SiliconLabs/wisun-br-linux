/*
 * SPDX-License-Identifier: LicenseRef-MSLA
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
#ifndef IOBUF_H
#define IOBUF_H
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "common/int24.h"

/*
 * Helper structures to pack/unpack data in buffers. It provides two different
 * APIs: write and read.
 *
 * For writing, the underlying buffer is allocated on first call to iobuf_push_*
 * and is enlarged each time it is necessary (thus, users do not have to compute
 * the size of the buffer to be allocated). iobuf_free() MUST be called to
 * release the memory. At anytime, the user can retrieve the content of the
 * buffer with the fields data and len.
 *
 * For reading, the caller has to set the fields data/data_size to the start/len
 * of the buffer he wants to parse. It is possible to have several iobufs
 * pointing to the same buffer (for nested structures). If an error (mostly a
 * buffer overflow) occurs during call of iobuf_pop_*(), 0 is returned and
 * iobuf.err is set. Thus, when parsing a series of fields, checking for
 * iobuf.err only once at the end is sufficient. One can additionally make sure
 * that there is no data remaining in the buffer using iobuf_remaining_size().
 *
 * The remaining data can be accessed without moving the read cursor using
 * iobuf_ptr() (and iobuf_remaining_size()).
 */

struct iobuf_write {
    int data_size;
    int len;
    uint8_t *data;
};

struct iobuf_read {
    int data_size;
    int cnt;
    bool err;
    const uint8_t *data;
};

void iobuf_push_u8(struct iobuf_write *buf, uint8_t val);
void iobuf_push_be16(struct iobuf_write *buf, uint16_t val);
void iobuf_push_le16(struct iobuf_write *buf, uint16_t val);
void iobuf_push_be24(struct iobuf_write *buf, uint24_t val);
void iobuf_push_le24(struct iobuf_write *buf, uint24_t val);
void iobuf_push_be32(struct iobuf_write *buf, uint32_t val);
void iobuf_push_le32(struct iobuf_write *buf, uint32_t val);
void iobuf_push_be64(struct iobuf_write *buf, uint64_t val);
void iobuf_push_le64(struct iobuf_write *buf, uint64_t val);
void iobuf_push_data(struct iobuf_write *buf, const void *val, int num);
void iobuf_push_data_reserved(struct iobuf_write *buf, const int num);
void iobuf_free(struct iobuf_write *buf);

uint8_t iobuf_pop_u8(struct iobuf_read *buf);
uint16_t iobuf_pop_be16(struct iobuf_read *buf);
uint16_t iobuf_pop_le16(struct iobuf_read *buf);
uint24_t iobuf_pop_be24(struct iobuf_read *buf);
uint24_t iobuf_pop_le24(struct iobuf_read *buf);
uint32_t iobuf_pop_be32(struct iobuf_read *buf);
uint32_t iobuf_pop_le32(struct iobuf_read *buf);
uint64_t iobuf_pop_be64(struct iobuf_read *buf);
uint64_t iobuf_pop_le64(struct iobuf_read *buf);
const uint8_t *iobuf_pop_data_ptr(struct iobuf_read *buf, size_t size);
void iobuf_pop_data(struct iobuf_read *buf, uint8_t *val, size_t size);
int iobuf_remaining_size(const struct iobuf_read *buf);
const uint8_t *iobuf_ptr(const struct iobuf_read *buf);

#endif
