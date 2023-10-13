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

struct iobuf_read;
struct iobuf_write;

void hif_push_bool(struct iobuf_write *buf, bool val);
void hif_push_uint(struct iobuf_write *buf, unsigned int val);
void hif_push_u8(struct iobuf_write *buf, uint8_t val);
void hif_push_u16(struct iobuf_write *buf, uint16_t val);
void hif_push_u32(struct iobuf_write *buf, uint32_t val);
void hif_push_u64(struct iobuf_write *buf, uint64_t val);
void hif_push_i8(struct iobuf_write *buf, int8_t val);
void hif_push_i16(struct iobuf_write *buf, int16_t val);
void hif_push_i32(struct iobuf_write *buf, int32_t val);
void hif_push_str(struct iobuf_write *buf, const char *val);
void hif_push_fixed_u8_array(struct iobuf_write *buf, const uint8_t *val, int num);
void hif_push_fixed_u16_array(struct iobuf_write *buf, const uint16_t *val, int num);
void hif_push_fixed_u32_array(struct iobuf_write *buf, const uint32_t *val, int num);
void hif_push_data(struct iobuf_write *buf, const uint8_t *val, size_t size);
void hif_push_raw(struct iobuf_write *buf, const uint8_t *val, size_t size);

bool hif_pop_bool(struct iobuf_read *buf);
unsigned int hif_pop_uint(struct iobuf_read *buf);
uint8_t  hif_pop_u8(struct iobuf_read *buf);
uint16_t hif_pop_u16(struct iobuf_read *buf);
uint32_t hif_pop_u32(struct iobuf_read *buf);
uint64_t hif_pop_u64(struct iobuf_read *buf);
int8_t   hif_pop_i8(struct iobuf_read *buf);
int16_t  hif_pop_i16(struct iobuf_read *buf);
int32_t  hif_pop_i32(struct iobuf_read *buf);
const char *hif_pop_str(struct iobuf_read *buf);
void hif_pop_fixed_u8_array(struct iobuf_read *buf, uint8_t *val, int num);
void hif_pop_fixed_u16_array(struct iobuf_read *buf, uint16_t *val, int num);
void hif_pop_fixed_u32_array(struct iobuf_read *buf, uint32_t *val, int num);
unsigned int hif_pop_data(struct iobuf_read *buf, uint8_t *val, unsigned int size);
unsigned int hif_pop_data_ptr(struct iobuf_read *buf, const uint8_t **val);
unsigned int hif_pop_raw(struct iobuf_read *buf, uint8_t *val, unsigned int size);
unsigned int hif_pop_raw_ptr(struct iobuf_read *buf, const uint8_t **val);

unsigned int __hif_pop_uint(struct iobuf_read *buf);

#endif
