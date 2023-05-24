#include "tools/fuzz/wsbrd_fuzz.h"
#include "tools/fuzz/rand.h"

ssize_t __real_getrandom(void *buf, size_t buflen, unsigned int flags);
ssize_t fuzz_real_getrandom(void *buf, size_t buflen, unsigned int flags)
{
    return __real_getrandom(buf, buflen, flags);
}

int main(int argc, char *argv[])
{
    return wsbr_fuzz_main(argc, argv);
}
