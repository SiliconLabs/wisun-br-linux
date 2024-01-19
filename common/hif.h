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
#include <stddef.h>

struct iobuf_read;
struct iobuf_write;

enum {
    HIF_CMD_REQ_NOP                  = 0x01,
    HIF_CMD_IND_NOP                  = 0x02,
    HIF_CMD_REQ_RESET                = 0x03,
    HIF_CMD_IND_RESET                = 0x04,
    HIF_CMD_IND_FATAL                = 0x05,
    HIF_CMD_SET_HOST_API             = 0x06,
    HIF_CMD_REQ_DATA_TX              = 0x10,
    HIF_CMD_REQ_DATA_TX_ABORT        = 0x11,
    HIF_CMD_CNF_DATA_TX              = 0x12,
    HIF_CMD_IND_DATA_RX              = 0x13,
    HIF_CMD_REQ_RADIO_ENABLE         = 0x20,
    HIF_CMD_REQ_RADIO_LIST           = 0x21,
    HIF_CMD_CNF_RADIO_LIST           = 0x22,
    HIF_CMD_SET_RADIO                = 0x23,
    HIF_CMD_SET_RADIO_REGULATION     = 0x24,
    HIF_CMD_SET_RADIO_TX_POWER       = 0x25,
    HIF_CMD_SET_FHSS_UC              = 0x30,
    HIF_CMD_SET_FHSS_FFN_BC          = 0x31,
    HIF_CMD_SET_FHSS_LFN_BC          = 0x32,
    HIF_CMD_SET_FHSS_ASYNC           = 0x33,
    HIF_CMD_SET_SEC_KEY              = 0x40,
    HIF_CMD_SET_SEC_FRAME_COUNTER_TX = 0x41,
    HIF_CMD_SET_SEC_FRAME_COUNTER_RX = 0x42,
    HIF_CMD_REQ_FILTER_CONFIGURE     = 0x50,
    HIF_CMD_SET_FILTER_MIN_RSSI      = 0x58,
    HIF_CMD_SET_FILTER_DST64         = 0x59,
    HIF_CMD_SET_FILTER_DST16         = 0x5a,
    HIF_CMD_SET_FILTER_PANID         = 0x5b,
    HIF_CMD_SET_FILTER_SRC64         = 0x5c,
    HIF_CMD_SET_FILTER_SRC16         = 0x5d,
    HIF_CMD_IND_CRC_ERROR            = 0xe0,
    HIF_CMD_REQ_PING                 = 0xe1,
    HIF_CMD_CNF_PING                 = 0xe2,
    HIF_CMD_IND_REPLAY_TIMER         = 0xf0,
    HIF_CMD_IND_REPLAY_SOCKET        = 0xf1,
};

enum hif_reg {
    HIF_REG_NONE = 0,
    HIF_REG_FCC  = 1,
    HIF_REG_ARIB = 2,
    HIF_REG_ETSI = 3,
};

const char *hif_cmd_str(uint8_t cmd);

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
