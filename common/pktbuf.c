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

void *pktbuf_push_head(struct pktbuf *pktbuf, const void *buf, size_t buf_len)
{
    if (pktbuf->err)
        return NULL;
    if (pktbuf_len_head(pktbuf) < buf_len)
        pktbuf_extend_head(pktbuf, buf_len - pktbuf_len_head(pktbuf));
    if (buf)
        memcpy(pktbuf_head(pktbuf) - buf_len, buf, buf_len);
    else
        memset(pktbuf_head(pktbuf) - buf_len, 0, buf_len);
    pktbuf->offset_head -= buf_len;
    return pktbuf_head(pktbuf);
}

void *pktbuf_push_tail(struct pktbuf *pktbuf, const void *buf, size_t buf_len)
{
    if (pktbuf->err)
        return NULL;
    if (pktbuf_len_tail(pktbuf) < buf_len)
        pktbuf_extend_tail(pktbuf, buf_len - pktbuf_len_tail(pktbuf));
    if (buf)
        memcpy(pktbuf_tail(pktbuf), buf, buf_len);
    else
        memset(pktbuf_tail(pktbuf), 0, buf_len);
    pktbuf->offset_tail += buf_len;
    return pktbuf_tail(pktbuf) - buf_len;
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

#define PKTBUF_PUSH_DEFINE(at, endian, bits) \
    void pktbuf_push_##at##_##endian##bits(struct pktbuf *pktbuf, uint##bits##_t val) \
    { \
        pktbuf_push_##at(pktbuf, (uint##bits##_t[1]){ hto##endian##bits(val) }, bits / 8); \
    }

#define htou8(x)   (x)
#define htobe24(x) htobe32((x) << 8)
#define htole24(x) htole32((x) & 0xffffff)

PKTBUF_PUSH_DEFINE(head, u,   8)
PKTBUF_PUSH_DEFINE(head, be, 16)
PKTBUF_PUSH_DEFINE(head, le, 16)
PKTBUF_PUSH_DEFINE(head, be, 24)
PKTBUF_PUSH_DEFINE(head, le, 24)
PKTBUF_PUSH_DEFINE(head, be, 32)
PKTBUF_PUSH_DEFINE(head, le, 32)
PKTBUF_PUSH_DEFINE(head, be, 64)
PKTBUF_PUSH_DEFINE(head, le, 64)
PKTBUF_PUSH_DEFINE(tail, u,   8)
PKTBUF_PUSH_DEFINE(tail, be, 16)
PKTBUF_PUSH_DEFINE(tail, le, 16)
PKTBUF_PUSH_DEFINE(tail, be, 24)
PKTBUF_PUSH_DEFINE(tail, le, 24)
PKTBUF_PUSH_DEFINE(tail, be, 32)
PKTBUF_PUSH_DEFINE(tail, le, 32)
PKTBUF_PUSH_DEFINE(tail, be, 64)
PKTBUF_PUSH_DEFINE(tail, le, 64)

#define PKTBUF_POP_DEFINE(at, endian, bits) \
    uint##bits##_t pktbuf_pop_##at##_##endian##bits(struct pktbuf *pktbuf) \
    {                                            \
        uint##bits##_t val;                      \
                                                 \
        pktbuf_pop_##at(pktbuf, &val, bits / 8); \
        return endian##bits##toh(val);           \
    }

#define u8toh(x)   (x)
#define be24toh(x) be32toh((x) >> 8)
#define le24toh(x) le32toh((x) & 0xffffff)

PKTBUF_POP_DEFINE(head, u,   8)
PKTBUF_POP_DEFINE(head, be, 16)
PKTBUF_POP_DEFINE(head, le, 16)
PKTBUF_POP_DEFINE(head, be, 24)
PKTBUF_POP_DEFINE(head, le, 24)
PKTBUF_POP_DEFINE(head, be, 32)
PKTBUF_POP_DEFINE(head, le, 32)
PKTBUF_POP_DEFINE(head, be, 64)
PKTBUF_POP_DEFINE(head, le, 64)
PKTBUF_POP_DEFINE(tail, u,   8)
PKTBUF_POP_DEFINE(tail, be, 16)
PKTBUF_POP_DEFINE(tail, le, 16)
PKTBUF_POP_DEFINE(tail, be, 24)
PKTBUF_POP_DEFINE(tail, le, 24)
PKTBUF_POP_DEFINE(tail, be, 32)
PKTBUF_POP_DEFINE(tail, le, 32)
PKTBUF_POP_DEFINE(tail, be, 64)
PKTBUF_POP_DEFINE(tail, le, 64)
