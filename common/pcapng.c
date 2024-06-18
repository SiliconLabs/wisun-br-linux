/*
 * SPDX-License-Identifier: LicenseRef-MSLA
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
#include <stddef.h>
#include <string.h>

#include "common/iobuf.h"
#include "common/log.h"

#include "pcapng.h"

#define PCAPNG_BLOCK_TYPE_SHB 0x0A0D0D0A
#define PCAPNG_BLOCK_TYPE_IDB 0x00000001
#define PCAPNG_BLOCK_TYPE_EPB 0x00000006

#define PCAPNG_BYTE_ORDER_MAGIC 0x1A2B3C4D

// Section Header Block
struct pcapng_shb {
    uint32_t byteorder_magic;
    uint16_t version_maj;
    uint16_t version_min;
    int64_t  section_len;
} __attribute__((packed));

// Interface Description Block
struct pcapng_idb {
    uint16_t link_type;
    uint16_t reserved;
    uint32_t snap_len;
} __attribute__((packed));

// Enhanced Packet Block
struct pcapng_epb {
    uint32_t ifindex;
    uint32_t timestamp_high;
    uint32_t timestamp_low;
    uint32_t pkt_len;
    uint32_t pkt_len_og;
} __attribute__((packed));

static int pcapng_block_start(struct iobuf_write *buf, uint32_t type)
{
    int offset = buf->len;

    iobuf_push_data(buf, &type, sizeof(type));
    iobuf_push_data_reserved(buf, sizeof(uint32_t)); // Block Total Length
    return offset;
}

static void pcapng_block_end(struct iobuf_write *buf, int offset)
{
    uint32_t len = buf->len + sizeof(uint32_t) - offset;

    memcpy(buf->data + offset + sizeof(uint32_t), &len, sizeof(len));
    iobuf_push_data(buf, &len, sizeof(len)); // Block Total Length
}

void pcapng_write_shb(struct iobuf_write *buf)
{
    struct pcapng_shb shb = {
        .byteorder_magic = PCAPNG_BYTE_ORDER_MAGIC,
        .version_maj = 1,
        .version_min = 0,
        .section_len = -1, // Unknown
    };
    int offset;

    offset = pcapng_block_start(buf, PCAPNG_BLOCK_TYPE_SHB);
    iobuf_push_data(buf, &shb, sizeof(shb));
    pcapng_block_end(buf, offset);
}

void pcapng_write_idb(struct iobuf_write *buf, uint16_t link_type)
{
    struct pcapng_idb idb = {
        .link_type = link_type,
        .snap_len  = 0, // No packet size restriction
    };
    int offset;

    offset = pcapng_block_start(buf, PCAPNG_BLOCK_TYPE_IDB);
    iobuf_push_data(buf, &idb, sizeof(idb));
    pcapng_block_end(buf, offset);
}

void pcapng_write_epb(struct iobuf_write *buf,
                      uint64_t timestamp_us,
                      const void *pkt, size_t pkt_len)
{
    struct pcapng_epb epb = {
        .ifindex = 0,
        .timestamp_high = timestamp_us >> 32,
        .timestamp_low  = timestamp_us,
        .pkt_len    = pkt_len,
        .pkt_len_og = pkt_len,
    };
    int offset;

    offset = pcapng_block_start(buf, PCAPNG_BLOCK_TYPE_EPB);
    iobuf_push_data(buf, &epb, sizeof(epb));
    iobuf_push_data(buf, pkt, pkt_len);
    while (buf->len % sizeof(uint32_t))
        iobuf_push_u8(buf, 0); // pad to 32 bits
    pcapng_block_end(buf, offset);
}
