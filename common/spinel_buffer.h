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
#ifndef SPINEL_BUFFER_H
#define SPINEL_BUFFER_H
#include <stdbool.h>
#include <stdint.h>

#include "log.h"

struct iobuf_write;

struct spinel_buffer {
    int len; // Length of the data in frame or size of the frame buffer
    int cnt; // Index of the already handled data or pointer to end of frame
    bool err;
    uint8_t frame[];
};

#define ALLOC_STACK_SPINEL_BUF(SIZE) ({                        \
    struct spinel_buffer *_tmp = alloca(SIZE + sizeof(*_tmp)); \
    _tmp->cnt = 0;                                             \
    _tmp->len = SIZE;                                          \
    _tmp->err = false;                                         \
    _tmp;                                                      \
})

int spinel_remaining_size(const struct spinel_buffer *buf);
uint8_t *spinel_ptr(struct spinel_buffer *buf);
void spinel_reset(struct spinel_buffer *buf);

void spinel_push_bool(struct iobuf_write *buf, bool val);
void spinel_push_uint(struct iobuf_write *buf, unsigned int val);
void spinel_push_u8(struct iobuf_write *buf, uint8_t val);
void spinel_push_u16(struct iobuf_write *buf, uint16_t val);
void spinel_push_u32(struct iobuf_write *buf, uint32_t val);
void spinel_push_i8(struct iobuf_write *buf, int8_t val);
void spinel_push_i16(struct iobuf_write *buf, int16_t val);
void spinel_push_i32(struct iobuf_write *buf, int32_t val);
void spinel_push_str(struct iobuf_write *buf, const char *val);
void spinel_push_fixed_u8_array(struct iobuf_write *buf, const uint8_t *val, int num);
void spinel_push_fixed_u16_array(struct iobuf_write *buf, const uint16_t *val, int num);
void spinel_push_fixed_u32_array(struct iobuf_write *buf, const uint32_t *val, int num);
void spinel_push_data(struct iobuf_write *buf, const uint8_t *val, size_t size);
void spinel_push_raw(struct iobuf_write *buf, const uint8_t *val, size_t size);

bool spinel_pop_bool(struct spinel_buffer *buf);
unsigned int spinel_pop_uint(struct spinel_buffer *buf);
uint8_t spinel_pop_u8(struct spinel_buffer *buf);
uint16_t spinel_pop_u16(struct spinel_buffer *buf);
uint32_t spinel_pop_u32(struct spinel_buffer *buf);
int8_t spinel_pop_i8(struct spinel_buffer *buf);
int16_t spinel_pop_i16(struct spinel_buffer *buf);
int32_t spinel_pop_i32(struct spinel_buffer *buf);
const char *spinel_pop_str(struct spinel_buffer *buf);
void spinel_pop_fixed_u8_array(struct spinel_buffer *buf, uint8_t *val, int num);
void spinel_pop_fixed_u16_array(struct spinel_buffer *buf, uint16_t *val, int num);
void spinel_pop_fixed_u32_array(struct spinel_buffer *buf, uint32_t *val, int num);
unsigned int spinel_pop_data(struct spinel_buffer *buf, uint8_t *val, unsigned int size);
unsigned int spinel_pop_data_ptr(struct spinel_buffer *buf, uint8_t **val);
unsigned int spinel_pop_raw(struct spinel_buffer *buf, uint8_t *val, unsigned int size);
unsigned int spinel_pop_raw_ptr(struct spinel_buffer *buf, uint8_t **val);

const char *spinel_cmd_str(int cmd);
const char *spinel_prop_str(int prop);
bool spinel_prop_is_valid(struct spinel_buffer *buf, int prop);
void spinel_trace(struct spinel_buffer *buf, const char *prefix);
void spinel_trace_tx(struct iobuf_write *buf);

#endif
