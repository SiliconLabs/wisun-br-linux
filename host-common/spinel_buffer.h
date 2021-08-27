/*
 * License: GPLv2
 * Created: 2021-06-28 14:56:22
 * Copyright 2021, Silicon Labs
 * Main authors:
 *    - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
#ifndef SPINEL_BUFFER_H
#define SPINEL_BUFFER_H
#include <stdint.h>

#include "spinel.h"
#include "log.h"

struct spinel_buffer {
    int len; // Length of the data in frame or size of the frame buffer
    int cnt; // Index of the already hanled data or pointer to end of frame
    uint8_t frame[];
};

#define ALLOC_STACK_SPINEL_BUF(SIZE) ({                        \
    struct spinel_buffer *_tmp = alloca(SIZE + sizeof(*_tmp)); \
    _tmp->cnt = 0;                                             \
    _tmp->len = SIZE;                                          \
    _tmp;                                                      \
})

int spinel_remaining_size(const struct spinel_buffer *buf);
uint8_t *spinel_ptr(struct spinel_buffer *buf);
void spinel_reset(struct spinel_buffer *buf);

void spinel_push_bool(struct spinel_buffer *buf, bool val);
void spinel_push_int(struct spinel_buffer *buf, int val);
void spinel_push_u8(struct spinel_buffer *buf, uint8_t val);
void spinel_push_u16(struct spinel_buffer *buf, uint16_t val);
void spinel_push_u32(struct spinel_buffer *buf, uint32_t val);
void spinel_push_i8(struct spinel_buffer *buf, int8_t val);
void spinel_push_i16(struct spinel_buffer *buf, int16_t val);
void spinel_push_i32(struct spinel_buffer *buf, int32_t val);
void spinel_push_str(struct spinel_buffer *buf, const char *val);
void spinel_push_fixed_u8_array(struct spinel_buffer *buf, const uint8_t *val, int num);
void spinel_push_fixed_u16_array(struct spinel_buffer *buf, const uint16_t *val, int num);
void spinel_push_fixed_u32_array(struct spinel_buffer *buf, const uint32_t *val, int num);
void spinel_push_data(struct spinel_buffer *buf, const uint8_t *val, size_t size);
void spinel_push_raw(struct spinel_buffer *buf, const uint8_t *val, size_t size);

bool spinel_pop_bool(struct spinel_buffer *buf);
int spinel_pop_int(struct spinel_buffer *buf);
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
unsigned int spinel_pop_raw(struct spinel_buffer *buf, uint8_t *val, unsigned int size, bool check_exact_size);
unsigned int spinel_pop_raw_ptr(struct spinel_buffer *buf, uint8_t **val, unsigned int size, bool check_exact_size);

void spinel_trace(const uint8_t *buf, int len, const char *prefix);

#endif
