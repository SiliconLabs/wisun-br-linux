#include <stddef.h>
#include <string.h>

#include "stack-services/common_functions.h"
#include "common/log.h"
#include "pcapng.h"

#define PCAPNG_BLOCK_TYPE_SHB 0x0A0D0D0A
#define PCAPNG_BLOCK_TYPE_IDB 0x00000001
#define PCAPNG_BLOCK_TYPE_EPB 0x00000006

#define PCAPNG_BYTE_ORDER_MAGIC 0x1A2B3C4D

void pcapng_write_shb(struct pcapng_buf *buf, const struct pcapng_shb *shb)
{
    const uint32_t len = PCAPNG_SHB_SIZE_MIN;
    uint8_t *ptr = buf->buf + buf->cnt;

    BUG_ON(buf->len - buf->cnt < len);
    ptr = common_write_32_bit_inverse(PCAPNG_BLOCK_TYPE_SHB, ptr);
    ptr = common_write_32_bit_inverse(len, ptr);
    ptr = common_write_32_bit_inverse(PCAPNG_BYTE_ORDER_MAGIC, ptr);
    ptr = common_write_16_bit_inverse(shb->version_maj, ptr);
    ptr = common_write_16_bit_inverse(shb->version_min, ptr);
    ptr = common_write_64_bit_inverse(shb->section_len, ptr);
    // options not supported
    ptr = common_write_32_bit_inverse(len, ptr);
    buf->cnt += len;
}

void pcapng_write_idb(struct pcapng_buf *buf, const struct pcapng_idb *idb)
{
    const uint32_t len = PCAPNG_IDB_SIZE_MIN;
    uint8_t *ptr = buf->buf + buf->cnt;

    BUG_ON(buf->len - buf->cnt < len);
    ptr = common_write_32_bit_inverse(PCAPNG_BLOCK_TYPE_IDB, ptr);
    ptr = common_write_32_bit_inverse(len, ptr);
    ptr = common_write_16_bit_inverse(idb->link_type, ptr);
    ptr = common_write_16_bit_inverse(0, ptr);
    ptr = common_write_32_bit_inverse(idb->snap_len, ptr);
    // options not supported
    ptr = common_write_32_bit_inverse(len, ptr);
    buf->cnt += len;
}

void pcapng_write_epb(struct pcapng_buf *buf, const struct pcapng_epb *epb)
{
    const uint8_t pkt_len_pad = (4 - (epb->pkt_len & 0b11)) & 0b11; // pad to 32 bits
    const uint32_t len = PCAPNG_EPB_SIZE_MIN + epb->pkt_len + pkt_len_pad;
    uint8_t *ptr = buf->buf + buf->cnt;

    BUG_ON(buf->len - buf->cnt < len);
    ptr = common_write_32_bit_inverse(PCAPNG_BLOCK_TYPE_EPB, ptr);
    ptr = common_write_32_bit_inverse(len, ptr);
    ptr = common_write_32_bit_inverse(epb->if_id, ptr);
    ptr = common_write_32_bit_inverse(epb->timestamp.tv_sec, ptr);
    ptr = common_write_32_bit_inverse(epb->timestamp.tv_nsec, ptr);
    ptr = common_write_32_bit_inverse(epb->pkt_len, ptr);
    ptr = common_write_32_bit_inverse(epb->pkt_len_og, ptr);
    memcpy(ptr, epb->pkt, epb->pkt_len);
    ptr += epb->pkt_len;
    memset(ptr, 0, pkt_len_pad);
    ptr += pkt_len_pad;
    // options not supported
    ptr = common_write_32_bit_inverse(len, ptr);
    buf->cnt += len;
}
