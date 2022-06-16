#ifndef TIMERS_H
#define TIMERS_H

struct wsbr_ctxt;
struct spinel_buffer;

void wsbr_common_timer_init(struct wsbr_ctxt *ctxt);
void wsbr_common_timer_process(struct wsbr_ctxt *ctxt);

void wsbr_spinel_replay_timers(struct spinel_buffer *buf);

#endif
