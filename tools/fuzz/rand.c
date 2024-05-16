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
#include <sys/types.h>
#include <stdint.h>

#include "tools/fuzz/wsbrd_fuzz.h"
#include "rand.h"

ssize_t __wrap_xgetrandom(void *buf, size_t buf_len, unsigned int flags)
{
    struct fuzz_ctxt *ctxt = &g_fuzz_ctxt;
    uint8_t *buf8 = buf;

    if (!ctxt->fuzzing_enabled || buf_len <= 8)
        return fuzz_real_getrandom(buf, buf_len, flags);

    // In most of the cases, when the stack ask for an array of random uint8_t,
    // it is initializing a key or seed for cryptographic material. In this
    // case, returning very predictable data simplify frames replay
    for (size_t i = 0; i < buf_len; i++)
        buf8[i] = i + 1;
    return buf_len;
}
