/*
 * SPDX-License-Identifier: LicenseRef-MSLA
 * Copyright (c) 2022 Silicon Laboratories Inc. (www.silabs.com)
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
#ifndef STRING_EXTRA_H_
#define STRING_EXTRA_H_
#include <stdint.h>
#include <string.h>

/*
 * Provide some non-standard extentions to string.h.
 *
 * These functions keep the same name and call conventions than string.h.
 */

static inline int memzcmp(const void *src, size_t size)
{
    const uint8_t *buf = src;

    if (!size)
        return 0;
    if (*buf)
        return 1;
    return memcmp(buf, buf + 1, size - 1);
}

static inline void memswap(void *buf1, void *buf2, size_t size)
{
    uint8_t *a = buf1;
    uint8_t *b = buf2;
    uint8_t tmp;

    for (int i = 0; i < size; i++) {
        tmp = a[i];
        a[i] = b[i];
        b[i] = tmp;
    }
}

#ifndef HAVE_STRLCPY
static inline size_t strlcpy(char *restrict dst, const char *restrict src, size_t dst_len)
{
    size_t src_len = strlen(src);

    if (src_len >= dst_len) {
        memcpy(dst, src, dst_len - 1);
        dst[dst_len - 1] = '\0';
    } else {
        memcpy(dst, src, src_len + 1);
    }
    return src_len;
}
#endif

#endif
