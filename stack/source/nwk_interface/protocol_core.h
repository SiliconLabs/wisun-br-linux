#ifndef PROTOCOL_CORE_H
#define PROTOCOL_CORE_H

void core_timer_event_handle(int ticksUpdate);
void nwk_bootstrap_timer(int ticks);
void icmp_slow_timer(int seconds);
void icmp_fast_timer(int ticks);
void update_reachable_time(int seconds);

#endif
