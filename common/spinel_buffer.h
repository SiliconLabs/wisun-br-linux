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
#ifndef SPINEL_BUFFER_H
#define SPINEL_BUFFER_H
#include <stdbool.h>
#include <stdint.h>

#include "log.h"

struct iobuf_read;
struct iobuf_write;

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

bool spinel_pop_bool(struct iobuf_read *buf);
unsigned int spinel_pop_uint(struct iobuf_read *buf);
uint8_t spinel_pop_u8(struct iobuf_read *buf);
uint16_t spinel_pop_u16(struct iobuf_read *buf);
uint32_t spinel_pop_u32(struct iobuf_read *buf);
int8_t spinel_pop_i8(struct iobuf_read *buf);
int16_t spinel_pop_i16(struct iobuf_read *buf);
int32_t spinel_pop_i32(struct iobuf_read *buf);
const char *spinel_pop_str(struct iobuf_read *buf);
void spinel_pop_fixed_u8_array(struct iobuf_read *buf, uint8_t *val, int num);
void spinel_pop_fixed_u16_array(struct iobuf_read *buf, uint16_t *val, int num);
void spinel_pop_fixed_u32_array(struct iobuf_read *buf, uint32_t *val, int num);
unsigned int spinel_pop_data(struct iobuf_read *buf, uint8_t *val, unsigned int size);
unsigned int spinel_pop_data_ptr(struct iobuf_read *buf, const uint8_t **val);
unsigned int spinel_pop_raw(struct iobuf_read *buf, uint8_t *val, unsigned int size);
unsigned int spinel_pop_raw_ptr(struct iobuf_read *buf, const uint8_t **val);

const char *spinel_cmd_str(int cmd);
const char *spinel_prop_str(int prop);
bool spinel_prop_is_valid(struct iobuf_read *buf, int prop);
void spinel_trace_tx(struct iobuf_write *buf);
void spinel_trace_rx(struct iobuf_read *buf);

#endif
