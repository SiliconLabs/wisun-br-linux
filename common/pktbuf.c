/*
 * SPDX-License-Identifier: LicenseRef-MSLA
 * Copyright (c) 2024 Silicon Laboratories Inc. (www.silabs.com)
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
#define _DEFAULT_SOURCE
#include <endian.h>
#include <stdlib.h>

#include "common/log.h"

#include "pktbuf.h"

static inline size_t pktbuf_len_head(const struct pktbuf *pktbuf)
{
    return pktbuf->offset_head;
}

static inline size_t pktbuf_len_tail(const struct pktbuf *pktbuf)
{
    return pktbuf->buf_len - pktbuf->offset_tail;
}

static inline uint8_t *pktbuf_tail(const struct pktbuf *pktbuf)
{
    return pktbuf->buf + pktbuf->offset_tail;
}

void pktbuf_init(struct pktbuf *pktbuf, const void *buf, size_t buf_len)
{
    pktbuf_free(pktbuf);
    pktbuf_push_tail(pktbuf, buf, buf_len);
}

void pktbuf_free(struct pktbuf *pktbuf)
{
    free(pktbuf->buf);
    memset(pktbuf, 0, sizeof(*pktbuf));
}

static void pktbuf_extend_tail(struct pktbuf *pktbuf, size_t len)
{
    pktbuf->buf_len += len;
    pktbuf->buf = realloc(pktbuf->buf, pktbuf->buf_len);
    FATAL_ON(!pktbuf->buf, 2, "%s: realloc %zu: %m", __func__, pktbuf->buf_len);
}

static void pktbuf_extend_head(struct pktbuf *pktbuf, size_t len)
{
    pktbuf_extend_tail(pktbuf, len);
    memmove(pktbuf_head(pktbuf) + len,
            pktbuf_head(pktbuf),
            pktbuf_len(pktbuf));
    pktbuf->offset_head += len;
    pktbuf->offset_tail += len;
}

void pktbuf_push_head(struct pktbuf *pktbuf, const void *buf, size_t buf_len)
{
    if (pktbuf->err)
        return;
    if (pktbuf_len_head(pktbuf) < buf_len)
        pktbuf_extend_head(pktbuf, buf_len - pktbuf_len_head(pktbuf));
    if (buf)
        memcpy(pktbuf_head(pktbuf) - buf_len, buf, buf_len);
    else
        memset(pktbuf_head(pktbuf) - buf_len, 0, buf_len);
    pktbuf->offset_head -= buf_len;
}

void pktbuf_push_tail(struct pktbuf *pktbuf, const void *buf, size_t buf_len)
{
    if (pktbuf->err)
        return;
    if (pktbuf_len_tail(pktbuf) < buf_len)
        pktbuf_extend_tail(pktbuf, buf_len - pktbuf_len_tail(pktbuf));
    if (buf)
        memcpy(pktbuf_tail(pktbuf), buf, buf_len);
    else
        memset(pktbuf_tail(pktbuf), 0, buf_len);
    pktbuf->offset_tail += buf_len;
}

void pktbuf_pop_head(struct pktbuf *pktbuf, void *buf, size_t buf_len)
{
    if (pktbuf->err || pktbuf_len(pktbuf) < buf_len) {
        pktbuf->err = true;
        if (buf)
            memset(buf, 0, buf_len);
        return;
    }
    if (buf)
        memcpy(buf, pktbuf_head(pktbuf), buf_len);
    pktbuf->offset_head += buf_len;
}

void pktbuf_pop_tail(struct pktbuf *pktbuf, void *buf, size_t buf_len)
{
    if (pktbuf->err || pktbuf_len(pktbuf) < buf_len) {
        pktbuf->err = true;
        if (buf)
            memset(buf, 0, buf_len);
        return;
    }
    if (buf)
        memcpy(buf, pktbuf_tail(pktbuf) - buf_len, buf_len);
    pktbuf->offset_tail -= buf_len;
}

void pktbuf_push_head_u8(struct pktbuf *pktbuf, uint8_t val)
{
    pktbuf_push_head(pktbuf, &val, sizeof(val));
}

void pktbuf_push_head_be16(struct pktbuf *pktbuf, uint16_t val)
{
    pktbuf_push_head(pktbuf, (uint16_t[1]){ htobe16(val) }, sizeof(val));
}

void pktbuf_push_head_le16(struct pktbuf *pktbuf, uint16_t val)
{
    pktbuf_push_head(pktbuf, (uint16_t[1]){ htole16(val) }, sizeof(val));
}

void pktbuf_push_head_be24(struct pktbuf *pktbuf, uint24_t val)
{
    pktbuf_push_head(pktbuf, (uint8_t *)(uint32_t[1]){ htobe32(val) } + 1, 3);
}

void pktbuf_push_head_le24(struct pktbuf *pktbuf, uint24_t val)
{
    pktbuf_push_head(pktbuf, (uint32_t[1]){ htole32(val) }, 3);
}

void pktbuf_push_head_be32(struct pktbuf *pktbuf, uint32_t val)
{
    pktbuf_push_head(pktbuf, (uint32_t[1]){ htobe32(val) }, sizeof(val));
}

void pktbuf_push_head_le32(struct pktbuf *pktbuf, uint32_t val)
{
    pktbuf_push_head(pktbuf, (uint32_t[1]){ htole32(val) }, sizeof(val));
}

void pktbuf_push_head_be64(struct pktbuf *pktbuf, uint64_t val)
{
    pktbuf_push_head(pktbuf, (uint64_t[1]){ htobe64(val) }, sizeof(val));
}

void pktbuf_push_head_le64(struct pktbuf *pktbuf, uint64_t val)
{
    pktbuf_push_head(pktbuf, (uint64_t[1]){ htole64(val) }, sizeof(val));
}

void pktbuf_push_tail_u8(struct pktbuf *pktbuf, uint8_t val)
{
    pktbuf_push_tail(pktbuf, &val, sizeof(val));
}

void pktbuf_push_tail_be16(struct pktbuf *pktbuf, uint16_t val)
{
    pktbuf_push_tail(pktbuf, (uint16_t[1]){ htobe16(val) }, sizeof(val));
}

void pktbuf_push_tail_le16(struct pktbuf *pktbuf, uint16_t val)
{
    pktbuf_push_tail(pktbuf, (uint16_t[1]){ htole16(val) }, sizeof(val));
}

void pktbuf_push_tail_be24(struct pktbuf *pktbuf, uint24_t val)
{
    pktbuf_push_head(pktbuf, (uint8_t *)(uint32_t[1]){ htobe32(val) } + 1, 3);
}

void pktbuf_push_tail_le24(struct pktbuf *pktbuf, uint24_t val)
{
    pktbuf_push_head(pktbuf, (uint32_t[1]){ htole32(val) }, 3);
}

void pktbuf_push_tail_be32(struct pktbuf *pktbuf, uint32_t val)
{
    pktbuf_push_tail(pktbuf, (uint32_t[1]){ htobe32(val) }, sizeof(val));
}

void pktbuf_push_tail_le32(struct pktbuf *pktbuf, uint32_t val)
{
    pktbuf_push_tail(pktbuf, (uint32_t[1]){ htole32(val) }, sizeof(val));
}

void pktbuf_push_tail_be64(struct pktbuf *pktbuf, uint64_t val)
{
    pktbuf_push_tail(pktbuf, (uint64_t[1]){ htobe64(val) }, sizeof(val));
}

void pktbuf_push_tail_le64(struct pktbuf *pktbuf, uint64_t val)
{
    pktbuf_push_tail(pktbuf, (uint64_t[1]){ htole64(val) }, sizeof(val));
}

uint8_t pktbuf_pop_head_u8(struct pktbuf *pktbuf)
{
    uint8_t val;

    pktbuf_pop_head(pktbuf, &val, sizeof(val));
    return val;
}

uint16_t pktbuf_pop_head_be16(struct pktbuf *pktbuf)
{
    uint16_t val;

    pktbuf_pop_head(pktbuf, &val, sizeof(val));
    return be16toh(val);
}

uint16_t pktbuf_pop_head_le16(struct pktbuf *pktbuf)
{
    uint16_t val;

    pktbuf_pop_head(pktbuf, &val, sizeof(val));
    return le16toh(val);
}

uint24_t pktbuf_pop_head_be24(struct pktbuf *pktbuf)
{
    uint32_t val = 0;

    pktbuf_pop_head(pktbuf, (uint8_t *)&val + 1, 3);
    return be32toh(val);
}

uint24_t pktbuf_pop_head_le24(struct pktbuf *pktbuf)
{
    uint32_t val = 0;

    pktbuf_pop_head(pktbuf, &val, 3);
    return le32toh(val);
}

uint32_t pktbuf_pop_head_be32(struct pktbuf *pktbuf)
{
    uint32_t val;

    pktbuf_pop_head(pktbuf, &val, sizeof(val));
    return be32toh(val);
}

uint32_t pktbuf_pop_head_le32(struct pktbuf *pktbuf)
{
    uint32_t val;

    pktbuf_pop_head(pktbuf, &val, sizeof(val));
    return le32toh(val);
}

uint64_t pktbuf_pop_head_be64(struct pktbuf *pktbuf)
{
    uint64_t val;

    pktbuf_pop_head(pktbuf, &val, sizeof(val));
    return be64toh(val);
}

uint64_t pktbuf_pop_head_le64(struct pktbuf *pktbuf)
{
    uint64_t val;

    pktbuf_pop_head(pktbuf, &val, sizeof(val));
    return le64toh(val);
}

uint8_t pktbuf_pop_tail_u8(struct pktbuf *pktbuf)
{
    uint8_t val;

    pktbuf_pop_head(pktbuf, &val, sizeof(val));
    return val;
}

uint16_t pktbuf_pop_tail_be16(struct pktbuf *pktbuf)
{
    uint16_t val;

    pktbuf_pop_head(pktbuf, &val, sizeof(val));
    return be16toh(val);
}

uint16_t pktbuf_pop_tail_le16(struct pktbuf *pktbuf)
{
    uint16_t val;

    pktbuf_pop_head(pktbuf, &val, sizeof(val));
    return le16toh(val);
}

uint24_t pktbuf_pop_tail_be24(struct pktbuf *pktbuf)
{
    uint32_t val = 0;

    pktbuf_pop_tail(pktbuf, (uint8_t *)&val + 1, 3);
    return be32toh(val);
}

uint24_t pktbuf_pop_tail_le24(struct pktbuf *pktbuf)
{
    uint32_t val = 0;

    pktbuf_pop_tail(pktbuf, &val, 3);
    return le32toh(val);
}

uint32_t pktbuf_pop_tail_be32(struct pktbuf *pktbuf)
{
    uint32_t val;

    pktbuf_pop_head(pktbuf, &val, sizeof(val));
    return be32toh(val);
}

uint32_t pktbuf_pop_tail_le32(struct pktbuf *pktbuf)
{
    uint32_t val;

    pktbuf_pop_head(pktbuf, &val, sizeof(val));
    return le32toh(val);
}

uint64_t pktbuf_pop_tail_be64(struct pktbuf *pktbuf)
{
    uint64_t val;

    pktbuf_pop_head(pktbuf, &val, sizeof(val));
    return be64toh(val);
}

uint64_t pktbuf_pop_tail_le64(struct pktbuf *pktbuf)
{
    uint64_t val;

    pktbuf_pop_head(pktbuf, &val, sizeof(val));
    return le64toh(val);
}
