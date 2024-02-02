#ifndef FUZZ_REPLAY_H
#define FUZZ_REPLAY_H

#include <stdint.h>

struct fuzz_ctxt;
struct iobuf_read;
struct rcp;
struct wsbr_ctxt;

void fuzz_ind_replay_timers(struct rcp *rcp, struct iobuf_read *buf);
void fuzz_trigger_timer(struct fuzz_ctxt *ctxt);

#endif
