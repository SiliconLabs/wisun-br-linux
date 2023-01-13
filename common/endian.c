/*
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
#include "endian.h"

uint16_t read_be16(const uint8_t ptr[2])
{
    uint16_t val = ptr[0] << 8
                 | ptr[1];
    return val;
}

uint16_t read_le16(const uint8_t ptr[2])
{
    uint16_t val = ptr[1] << 8
                 | ptr[0];
    return val;
}

uint24_t read_be24(const uint8_t ptr[3])
{
    uint24_t val = ptr[0] << 16
                 | ptr[1] << 8
                 | ptr[2];
    return val;
}

uint24_t read_le24(const uint8_t ptr[3])
{
    uint24_t val = ptr[2] << 16
                 | ptr[1] << 8
                 | ptr[0];
    return val;
}

uint32_t read_be32(const uint8_t ptr[4])
{
    uint32_t val = ptr[0] << 24
                 | ptr[1] << 16
                 | ptr[2] << 8
                 | ptr[3];
    return val;
}

uint32_t read_le32(const uint8_t ptr[4])
{
    uint32_t val = ptr[3] << 24
                 | ptr[2] << 16
                 | ptr[1] << 8
                 | ptr[0];
    return val;
}

uint64_t read_be64(const uint8_t ptr[8])
{
    uint64_t val = (uint64_t)ptr[0] << 56
                 | (uint64_t)ptr[1] << 48
                 | (uint64_t)ptr[2] << 40
                 | (uint64_t)ptr[3] << 32
                 | (uint64_t)ptr[4] << 24
                 | (uint64_t)ptr[5] << 16
                 | (uint64_t)ptr[6] << 8
                 | (uint64_t)ptr[7];
    return val;
}

uint64_t read_le64(const uint8_t ptr[8])
{
    uint64_t val = (uint64_t)ptr[7] << 56
                 | (uint64_t)ptr[6] << 48
                 | (uint64_t)ptr[5] << 40
                 | (uint64_t)ptr[4] << 32
                 | (uint64_t)ptr[3] << 24
                 | (uint64_t)ptr[2] << 16
                 | (uint64_t)ptr[1] << 8
                 | (uint64_t)ptr[0];
    return val;
}

uint8_t *write_be16(uint8_t ptr[2], uint16_t val)
{
    ptr[0] = val >> 8;
    ptr[1] = val;
    return ptr + 2;
}

uint8_t *write_le16(uint8_t ptr[2], uint16_t val)
{
    ptr[0] = val;
    ptr[1] = val >> 8;
    return ptr + 2;
}

uint8_t *write_be24(uint8_t ptr[3], uint24_t val)
{
    ptr[0] = val >> 16;
    ptr[1] = val >> 8;
    ptr[2] = val;
    return ptr + 3;
}

uint8_t *write_le24(uint8_t ptr[3], uint24_t val)
{
    ptr[0] = val;
    ptr[1] = val >> 8;
    ptr[2] = val >> 16;
    return ptr + 3;
}

uint8_t *write_be32(uint8_t ptr[4], uint32_t val)
{
    ptr[0] = val >> 24;
    ptr[1] = val >> 16;
    ptr[2] = val >> 8;
    ptr[3] = val;
    return ptr + 4;
}

uint8_t *write_le32(uint8_t ptr[4], uint32_t val)
{
    ptr[0] = val;
    ptr[1] = val >> 8;
    ptr[2] = val >> 16;
    ptr[3] = val >> 24;
    return ptr + 4;
}

uint8_t *write_be64(uint8_t ptr[8], uint64_t val)
{
    ptr[0] = val >> 56;
    ptr[1] = val >> 48;
    ptr[2] = val >> 40;
    ptr[3] = val >> 32;
    ptr[4] = val >> 24;
    ptr[5] = val >> 16;
    ptr[6] = val >> 8;
    ptr[7] = val;
    return ptr + 8;
}

uint8_t *write_le64(uint8_t ptr[8], uint64_t val)
{
    ptr[0] = val;
    ptr[1] = val >> 8;
    ptr[2] = val >> 16;
    ptr[3] = val >> 24;
    ptr[4] = val >> 32;
    ptr[5] = val >> 40;
    ptr[6] = val >> 48;
    ptr[7] = val >> 56;
    return ptr + 8;
}
