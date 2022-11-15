#ifndef PROTOCOL_CORE_H
#define PROTOCOL_CORE_H

void nwk_bootstrap_timer(int ticks);
void icmp_fast_timer(int ticks);
void update_reachable_time(int seconds);

#endif
