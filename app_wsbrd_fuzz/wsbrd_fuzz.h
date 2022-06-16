#ifndef WSBRD_FUZZ_H
#define WSBRD_FUZZ_H

#include <stdbool.h>

struct fuzz_ctxt {
    bool capture_enabled;
    bool replay_enabled;
    int uart_fd;
};

extern struct fuzz_ctxt g_fuzz_ctxt;

#endif
