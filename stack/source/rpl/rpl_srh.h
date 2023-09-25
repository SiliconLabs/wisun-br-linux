#ifndef RPL_SRH_H
#define RPL_SRH_H

#include <stdbool.h>
#include <stdint.h>

struct iobuf_write;
struct rpl_root;

//   Wi-SUN FAN 1.1v06 - 4.1.1 General
// The FAN MUST support mesh networking with FAN nodes being up to 24 hops from
// the root of the mesh tree.
#define WS_RPL_SRH_MAXSEG 24

// Decompressed source routing header
struct rpl_srh_decmpr {
    uint8_t seg_left;
    uint8_t seg_count;
    uint8_t seg_list[WS_RPL_SRH_MAXSEG][16];
};

int rpl_srh_build(struct rpl_root *root, const uint8_t dst[16],
                  struct rpl_srh_decmpr *srh, const uint8_t **nxthop);
void rpl_srh_push(struct iobuf_write *buf, const struct rpl_srh_decmpr *srh,
                  const uint8_t dst[16], uint8_t nxthdr);

#endif
