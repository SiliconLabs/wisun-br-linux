#ifndef WSBRD_FUZZ_H
#define WSBRD_FUZZ_H

#include <stdbool.h>
#include <time.h>

struct fuzz_ctxt {
    bool fuzzing_enabled;
    bool rand_predictable;
    time_t mbedtls_time;
    bool capture_enabled;
    bool replay_enabled;
    int uart_fd;
    int timer_counter;
    int tun_pipe[2];
};

extern struct fuzz_ctxt g_fuzz_ctxt;

#endif
