/*
 * Copyright (c) 2023 Silicon Laboratories Inc. (www.silabs.com)
 *
 * The licensor of this software is Silicon Laboratories Inc. Your use of this
 * software is governed by the terms of the Silicon Labs Master Software License
 * Agreement (MSLA) available at [1].  This software is distributed to you in
 * Object Code format and/or Source Code format and is governed by the sections
 * of the MSLA applicable to Object Code, Source Code and Modified Open Source
 * Code. By using this software, you agree to the terms of the MSLA.
 *
 * [1]: https://www.silabs.com/about-us/legal/master-software-license-agreement
 */
#ifndef PCAPNG_H
#define PCAPNG_H

// The pcapng format is specified in draft-tuexen-opsawg-pcapng
// https://datatracker.ietf.org/doc/html/draft-tuexen-opsawg-pcapng-05
// Only features required by the Wi-SUN TBU are implemented.

#include <stdint.h>
#include <alloca.h>
#include <time.h>

// Link types defined in draft-richardson-opsawg-pcaplinktype
// https://datatracker.ietf.org/doc/html/draft-richardson-opsawg-pcaplinktype-00
#define LINKTYPE_IEEE802_15_4_NOFCS 230

#define PCAPNG_SHB_SIZE_MIN (        \
    4 + /* Block Type             */ \
    4 + /* Block Total Length     */ \
    4 + /* Byte-Order Magic       */ \
    2 + /* Major Version          */ \
    2 + /* Minor Version          */ \
    8 + /* Section Length         */ \
    0 + /* Options                */ \
    4   /* Block Total Length     */ \
)
#define PCAPNG_IDB_SIZE_MIN (        \
    4 + /* Block Type             */ \
    4 + /* Block Total Length     */ \
    2 + /* LinkType               */ \
    2 + /* Reserved               */ \
    4 + /* SnapLen                */ \
    0 + /* Options                */ \
    4   /* Block Total Length     */ \
)
#define PCAPNG_EPB_SIZE_MIN (        \
    4 + /* Block Type             */ \
    4 + /* Block Total Length     */ \
    4 + /* Interface ID           */ \
    4 + /* Timestamp (High)       */ \
    4 + /* Timestamp (Low)        */ \
    4 + /* Captured Packet Length */ \
    4 + /* Original Packet Length */ \
    0 + /* Packet Data            */ \
    0 + /* Options                */ \
    4   /* Block Total Length     */ \
)

struct iobuf_write;

struct pcapng_shb {
    uint16_t version_maj;
    uint16_t version_min;
    int64_t section_len;
    // options not supported
};

struct pcapng_idb {
    uint16_t link_type;
    uint32_t snap_len;
    // options not supported
};

struct pcapng_epb {
    uint32_t if_id;
    uint64_t timestamp; // only us resolution supported (default)
    uint32_t pkt_len;
    uint32_t pkt_len_og;
    const uint8_t *pkt;
    // options not supported
};

void pcapng_write_shb(struct iobuf_write *buf, const struct pcapng_shb *shb);
void pcapng_write_idb(struct iobuf_write *buf, const struct pcapng_idb *idb);
void pcapng_write_epb(struct iobuf_write *buf, const struct pcapng_epb *epb);

#endif
