/*
 * SPDX-License-Identifier: LicenseRef-MSLA
 * Copyright (c) 2023 Silicon Laboratories Inc. (www.silabs.com)
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
#ifndef COMMON_CRC_H
#define COMMON_CRC_H
#include <stdbool.h>
#include <stdint.h>

#define CRC_INIT_HCS      0xffff
#define CRC_INIT_FCS      0xc6c6
#define CRC_INIT_LEGACY   0xffff
#define CRC_XOROUT_LEGACY 0xffff

uint16_t crc16(uint16_t crc, const uint8_t *data, int len);
bool crc_check(uint16_t init, const uint8_t *data, int len, uint16_t expected_crc);

#endif
