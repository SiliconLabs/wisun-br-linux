#ifndef RPL_GLUE_H
#define RPL_GLUE_H

#include <stdbool.h>
#include <stdint.h>

struct buffer;
struct net_if;
struct rpl_root;

// These functions handle the RPL IPv6 extensions in the legacy nanostack IPv6
// implementation.

void rpl_glue_init(struct net_if *net_if);

bool rpl_glue_process_rpi(struct rpl_root *root, struct buffer *buf,
                          const uint8_t *opt, uint8_t opt_len);

void rpl_glue_route_add(struct rpl_root *root, const uint8_t *prefix, size_t prefix_len);
void rpl_glue_route_del(struct rpl_root *root, const uint8_t *prefix, size_t prefix_len);

#endif
