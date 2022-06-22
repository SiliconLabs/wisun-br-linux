#ifndef WSBRD_FUZZ_H
#define WSBRD_FUZZ_H

#include <stdbool.h>
#include <time.h>

struct fuzz_ctxt {
    bool fuzzing_enabled;
    bool rand_predictable;
    time_t mbedtls_time;
    int uart_fd;
    int timer_counter;

    bool capture_enabled;
    bool capture_init_enabled;
    int capture_init_fd;

    bool replay_enabled;
    int tun_pipe[2];
};

extern struct fuzz_ctxt g_fuzz_ctxt;

#endif
