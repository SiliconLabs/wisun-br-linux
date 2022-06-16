#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>

#include "wsbrd_fuzz.h"

ssize_t __real_getrandom(void *buf, size_t buflen, unsigned int flags);
ssize_t __wrap_getrandom(void *buf, size_t buflen, unsigned int flags)
{
    static bool init = false;

    if (!g_fuzz_ctxt.rand_predictable)
        return __real_getrandom(buf, buflen, flags);
    
    if (!init) {
        srand(0);
        init = true;
    }

    for (size_t i = 0; i < buflen; i++)
        ((uint8_t *) buf)[i] = rand();

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
