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
#include <endian.h>
#include <string.h>

#include "endian.h"

uint16_t read_be16(const uint8_t ptr[2])
{
    return be16toh(*(const be16_t *)ptr);
}

uint16_t read_le16(const uint8_t ptr[2])
{
    return le16toh(*(const le16_t *)ptr);
}

uint24_t read_be24(const uint8_t ptr[3])
{
    be32_t val = 0;

    memcpy((uint8_t *)&val + 1, ptr, 3);
    return be32toh(val);
}

uint24_t read_le24(const uint8_t ptr[3])
{
    le32_t val = 0;

    memcpy(&val, ptr, 3);
    return le32toh(val);
}

uint32_t read_be32(const uint8_t ptr[4])
{
    return be32toh(*(const be32_t *)ptr);
}

uint32_t read_le32(const uint8_t ptr[4])
{
    return le32toh(*(const le32_t *)ptr);
}

uint64_t read_be64(const uint8_t ptr[8])
{
    return be64toh(*(const be64_t *)ptr);
}

uint64_t read_le64(const uint8_t ptr[8])
{
    return le64toh(*(const le64_t *)ptr);
}

uint8_t *write_be16(uint8_t ptr[2], uint16_t val)
{
    *(be16_t *)ptr = htobe16(val);
    return ptr + sizeof(val);
}

uint8_t *write_le16(uint8_t ptr[2], uint16_t val)
{
    *(le16_t *)ptr = htole16(val);
    return ptr + sizeof(val);
}

uint8_t *write_be24(uint8_t ptr[3], uint24_t val)
{
    val = htobe32(val);
    memcpy(ptr, (uint8_t *)&val + 1, 3);
    return ptr + 3;
}

uint8_t *write_le24(uint8_t ptr[3], uint24_t val)
{
    val = htole32(val);
    memcpy(ptr, &val, 3);
    return ptr + 3;
}

uint8_t *write_be32(uint8_t ptr[4], uint32_t val)
{
    *(be32_t *)ptr = htobe32(val);
    return ptr + sizeof(val);
}

uint8_t *write_le32(uint8_t ptr[4], uint32_t val)
{
    *(le32_t *)ptr = htole32(val);
    return ptr + sizeof(val);
}

uint8_t *write_be64(uint8_t ptr[8], uint64_t val)
{
    *(be64_t *)ptr = htobe64(val);
    return ptr + sizeof(val);
}

uint8_t *write_le64(uint8_t ptr[8], uint64_t val)
{
    *(le64_t *)ptr = htole64(val);
    return ptr + sizeof(val);
}
