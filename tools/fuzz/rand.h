#ifndef FUZZ_RAND_H
#define FUZZ_RAND_H

#include <sys/types.h>

/*
 * This function is exported so it can be defined to something other
 * than __real_getrandom outside of wsbrd-fuzz (eg. in libwsbrd-ns3).
 */

ssize_t fuzz_real_getrandom(void *buf, size_t buflen, unsigned int flags);

#endif
