/*
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
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>

#include "tools/fuzz/wsbrd_fuzz.h"
#include "rand.h"

ssize_t __wrap_getrandom(void *buf, size_t buflen, unsigned int flags)
{
    static bool init = false;
    uint8_t *buf8 = (uint8_t *) buf;

    if (!g_fuzz_ctxt.rand_predictable)
        return fuzz_real_getrandom(buf, buflen, flags);

    if (!init) {
        srand(0);
        init = true;
    }

    // In most of the cases, when the stack ask for an array of random uint8_t,
    // it is initializing a key or seed for cryptographic material. In this
    // case, returning very predictible data simplify frames replay
    if (g_fuzz_ctxt.fuzzing_enabled && buflen > 8) {
        for (size_t i = 0; i < buflen; i++)
            buf8[i] = i + 1;
    } else {
        for (size_t i = 0; i < buflen; i++)
            buf8[i] = rand();
    }

    return buflen;
}

// mbedtls uses time as source of entropy.
// time() is only used by mbedtls thankfully.
time_t __real_time(time_t *tloc);
time_t __wrap_time(time_t *tloc)
{
    if (!g_fuzz_ctxt.rand_predictable)
        return __real_time(tloc);

    if (tloc)
        *tloc = g_fuzz_ctxt.mbedtls_time;
    return g_fuzz_ctxt.mbedtls_time;
}
