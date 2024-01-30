#ifndef FUZZ_REPLAY_H
#define FUZZ_REPLAY_H

#include <stdint.h>

struct fuzz_ctxt;
struct iobuf_read;
struct wsbr_ctxt;

void fuzz_spinel_replay_timers(struct wsbr_ctxt *ctxt, uint32_t prop, struct iobuf_read *buf);
void fuzz_trigger_timer(struct fuzz_ctxt *ctxt);

#endif
