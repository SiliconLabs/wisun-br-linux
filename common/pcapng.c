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
#include <stddef.h>
#include <string.h>

#include "common/iobuf.h"
#include "common/log.h"
#include "pcapng.h"

#define PCAPNG_BLOCK_TYPE_SHB 0x0A0D0D0A
#define PCAPNG_BLOCK_TYPE_IDB 0x00000001
#define PCAPNG_BLOCK_TYPE_EPB 0x00000006

#define PCAPNG_BYTE_ORDER_MAGIC 0x1A2B3C4D

void pcapng_write_shb(struct iobuf_write *buf, const struct pcapng_shb *shb)
{
    const uint32_t len = PCAPNG_SHB_SIZE_MIN;

    iobuf_push_le32(buf, PCAPNG_BLOCK_TYPE_SHB);
    iobuf_push_le32(buf, len);
    iobuf_push_le32(buf, PCAPNG_BYTE_ORDER_MAGIC);
    iobuf_push_le16(buf, shb->version_maj);
    iobuf_push_le16(buf, shb->version_min);
    iobuf_push_le64(buf, shb->section_len);
    // options not supported
    iobuf_push_le32(buf, len);
}

void pcapng_write_idb(struct iobuf_write *buf, const struct pcapng_idb *idb)
{
    const uint32_t len = PCAPNG_IDB_SIZE_MIN;

    iobuf_push_le32(buf, PCAPNG_BLOCK_TYPE_IDB);
    iobuf_push_le32(buf, len);
    iobuf_push_le16(buf, idb->link_type);
    iobuf_push_le16(buf, 0);
    iobuf_push_le32(buf, idb->snap_len);
    // options not supported
    iobuf_push_le32(buf, len);
}

void pcapng_write_epb(struct iobuf_write *buf, const struct pcapng_epb *epb)
{
    const uint8_t pkt_len_pad = (4 - (epb->pkt_len & 0b11)) & 0b11; // pad to 32 bits
    const uint32_t len = PCAPNG_EPB_SIZE_MIN + epb->pkt_len + pkt_len_pad;

    iobuf_push_le32(buf, PCAPNG_BLOCK_TYPE_EPB);
    iobuf_push_le32(buf, len);
    iobuf_push_le32(buf, epb->if_id);
    iobuf_push_le32(buf, epb->timestamp >> 32);
    iobuf_push_le32(buf, epb->timestamp & 0xffffffff);
    iobuf_push_le32(buf, epb->pkt_len);
    iobuf_push_le32(buf, epb->pkt_len_og);
    iobuf_push_data(buf, epb->pkt, epb->pkt_len);
    for (int i = 0; i < pkt_len_pad; i++)
        iobuf_push_u8(buf, 0); // pad to 32 bits
    // options not supported
    iobuf_push_le32(buf, len);
}
