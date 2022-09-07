#ifndef WSBRD_FUZZ_H
#define WSBRD_FUZZ_H

#include <stdbool.h>
#include <time.h>

#include "interfaces.h"

struct fuzz_ctxt {
    bool fuzzing_enabled;
    bool rand_predictable;
    time_t mbedtls_time;
    int timer_counter;

    bool capture_enabled;
    bool capture_init_enabled;
    int capture_fd;
    int capture_init_fd;

    int replay_count;
    int replay_fds[10];
    int replay_i;
    int tun_pipe[2];
    int socket_pipe_count;
    int socket_pipes[IF_SOCKET_COUNT][2];
};

extern struct fuzz_ctxt g_fuzz_ctxt;

#endif
