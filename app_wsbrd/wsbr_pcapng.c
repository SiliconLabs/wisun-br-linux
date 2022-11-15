#define _DEFAULT_SOURCE
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include "stack-services/common_functions.h"
#include "common/log.h"
#include "common/iobuf.h"
#include "common/pcapng.h"
#include "common/string_extra.h"
#include "wsbr.h"

// Figure 7-2 Format of the Frame Control field
#define IEEE802154_FCF_FRAME_TYPE         0b0000000000000111
#define IEEE802154_FCF_SECURITY_ENABLED   0b0000000000001000
#define IEEE802154_FCF_FRAME_PENDING      0b0000000000010000
#define IEEE802154_FCF_ACK_REQ            0b0000000000100000
#define IEEE802154_FCF_PAN_ID_COMPRESSION 0b0000000001000000
#define IEEE802154_FCF_SEQ_NUM_SUPPR      0b0000000100000000
#define IEEE802154_FCF_SEQ_IE_PRESENT     0b0000001000000000
#define IEEE802154_FCF_DST_ADDR_MODE      0b0000110000000000
#define IEEE802154_FCF_FRAME_VERSION      0b0011000000000000
#define IEEE802154_FCF_SRC_ADDR_MODE      0b1100000000000000

// Table 7-1 Values of the Frame Type field
#define IEEE802154_FRAME_TYPE_DATA 0b001

// Figure 7-21 Format of Header IEs
#define IEEE802154_HEADER_IE_LEN_MASK  0b0000000001111111
#define IEEE802154_HEADER_IE_ID_MASK   0b0111111110000000
#define IEEE802154_HEADER_IE_TYPE_MASK 0b1000000000000000
#define IEEE802154_HEADER_IE(len, id) (               \
      FIELD_PREP(IEEE802154_HEADER_IE_LEN_MASK,  len) \
    | FIELD_PREP(IEEE802154_HEADER_IE_ID_MASK,   id ) \
    | FIELD_PREP(IEEE802154_HEADER_IE_TYPE_MASK, 0  ) \
)

// Figure 7-46 Format of Payload IEs
#define IEEE802154_PAYLOAD_IE_LEN_MASK  0b0000011111111111
#define IEEE802154_PAYLOAD_IE_ID_MASK   0b0111100000000000
#define IEEE802154_PAYLOAD_IE_TYPE_MASK 0b1000000000000000
#define IEEE802154_PAYLOAD_IE(len, id) (               \
      FIELD_PREP(IEEE802154_PAYLOAD_IE_LEN_MASK,  len) \
    | FIELD_PREP(IEEE802154_PAYLOAD_IE_ID_MASK,   id ) \
    | FIELD_PREP(IEEE802154_PAYLOAD_IE_TYPE_MASK, 1  ) \
)

// Table 7-7 Element IDs for Header IEs
#define IEEE802154_IE_ID_HT1 0x7e
#define IEEE802154_IE_ID_HT2 0x7f
// Table 7-15 Payload IE Group ID
#define IEEE802154_IE_ID_PT  0xf

// 7.4.2.17 Header Termination 1 IE
#define IEEE802154_IE_HT1 IEEE802154_HEADER_IE(0, IEEE802154_IE_ID_HT1)
// 7.4.2.18 Header Termination 2 IE
#define IEEE802154_IE_HT2 IEEE802154_HEADER_IE(0, IEEE802154_IE_ID_HT2)
// 7.4.3.3 Payload Termination IE
#define IEEE802154_IE_PT IEEE802154_PAYLOAD_IE(0, IEEE802154_IE_ID_PT)

// Table 7-2 PAN ID Compression field value for frame version 0b10
static const struct {
    uint8_t dst_addr_mode;
    uint8_t src_addr_mode;
    bool dst_pan_id;
    bool src_pan_id;
    bool pan_id_compression;
} ieee802154_table_pan_id_comp[] = {
    { MAC_ADDR_MODE_NONE,   MAC_ADDR_MODE_NONE,   false, false, 0 },
    { MAC_ADDR_MODE_NONE,   MAC_ADDR_MODE_NONE,   true,  false, 1 },
    { MAC_ADDR_MODE_16_BIT, MAC_ADDR_MODE_NONE,   true,  false, 0 },
    { MAC_ADDR_MODE_64_BIT, MAC_ADDR_MODE_NONE,   true,  false, 0 },
    { MAC_ADDR_MODE_16_BIT, MAC_ADDR_MODE_NONE,   false, false, 1 },
    { MAC_ADDR_MODE_64_BIT, MAC_ADDR_MODE_NONE,   false, false, 1 },
    { MAC_ADDR_MODE_NONE,   MAC_ADDR_MODE_16_BIT, false, true,  0 },
    { MAC_ADDR_MODE_NONE,   MAC_ADDR_MODE_64_BIT, false, true,  0 },
    { MAC_ADDR_MODE_NONE,   MAC_ADDR_MODE_16_BIT, false, false, 1 },
    { MAC_ADDR_MODE_NONE,   MAC_ADDR_MODE_64_BIT, false, false, 1 },
    { MAC_ADDR_MODE_64_BIT, MAC_ADDR_MODE_64_BIT, true,  false, 0 },
    { MAC_ADDR_MODE_64_BIT, MAC_ADDR_MODE_64_BIT, false, false, 1 },
    { MAC_ADDR_MODE_16_BIT, MAC_ADDR_MODE_16_BIT, true,  true,  0 },
    { MAC_ADDR_MODE_16_BIT, MAC_ADDR_MODE_64_BIT, true,  true,  0 },
    { MAC_ADDR_MODE_64_BIT, MAC_ADDR_MODE_16_BIT, true,  true,  0 },
    { MAC_ADDR_MODE_16_BIT, MAC_ADDR_MODE_64_BIT, true,  false, 1 },
    { MAC_ADDR_MODE_64_BIT, MAC_ADDR_MODE_16_BIT, true,  false, 1 },
    { MAC_ADDR_MODE_16_BIT, MAC_ADDR_MODE_16_BIT, true,  false, 1 },
};

// Table 7-6 termination IE inclusion rules
static const struct {
    bool header_ie;
    bool payload_ie;
    bool data_payload;
    uint16_t ie_ht;
    uint16_t ie_pt;
} ieee802154_table_term_ie[] = {
    { false, false, false, 0,                 0                },
    { true,  false, false, 0,                 0                },
    { false, true,  false, IEEE802154_IE_HT1, 0                },
    { true,  true,  false, IEEE802154_IE_HT1, 0                },
    { false, false, true,  0,                 0                },
    { true,  false, true,  IEEE802154_IE_HT2, 0                },
    { false, true,  true,  IEEE802154_IE_HT1, IEEE802154_IE_PT },
    { true,  true,  true,  IEEE802154_IE_HT1, IEEE802154_IE_PT },
};

static void wsbr_pcapng_write_start(struct wsbr_ctxt *ctxt);

static void wsbr_pcapng_write(struct wsbr_ctxt *ctxt, const struct iobuf_write *buf)
{
    int ret;

    // recover if other process stopped reading from FIFO
    if (ctxt->pcapng_fd < 0) {
        ctxt->pcapng_fd = open(ctxt->config.pcap_file, O_WRONLY | O_NONBLOCK);
        if (ctxt->pcapng_fd < 0)
            return;
        WARN("restarted pcapng capture");
        wsbr_pcapng_write_start(ctxt);
    }

    ret = write(ctxt->pcapng_fd, buf->data, buf->len);
    if (ret >= 0)
        return;
    if (ctxt->pcapng_type != S_IFIFO)
        FATAL(2, "write pcapng: %m");
    if (errno == EAGAIN)
        return;
    if (errno != EPIPE)
        FATAL(2, "write pcapng: %m");

    WARN("stopped pcapng capture");
    ret = close(ctxt->pcapng_fd);
    FATAL_ON(ret < 0, 2, "close pcapng: %m");
    ctxt->pcapng_fd = -1;
}

static void wsbr_pcapng_write_start(struct wsbr_ctxt *ctxt)
{
    static const struct pcapng_shb shb = {
        .version_maj = 1,
        .version_min = 0,
        .section_len = -1, // unknown section length
    };
    static const struct pcapng_idb idb = {
        .link_type = LINKTYPE_IEEE802_15_4_NOFCS,
        .snap_len = 0, // no packet size restriction
    };
    struct iobuf_write buf = { 0 };

    pcapng_write_shb(&buf, &shb);
    pcapng_write_idb(&buf, &idb);
    wsbr_pcapng_write(ctxt, &buf);
    iobuf_free(&buf);
}

void wsbr_pcapng_init(struct wsbr_ctxt *ctxt)
{
    struct stat statbuf;
    int ret;

    ret = stat(ctxt->config.pcap_file, &statbuf);
    if (ret) {
        if (errno == ENOENT)
            ctxt->pcapng_type = S_IFREG;
        else
            FATAL(2, "stat: %m");
    } else {
        ctxt->pcapng_type = statbuf.st_mode & S_IFMT;
    }
    if (ctxt->pcapng_type == S_IFIFO) {
        ctxt->pcapng_fd = open(ctxt->config.pcap_file, O_WRONLY | O_NONBLOCK);
        if (ctxt->pcapng_fd < 0) {
            if (errno == ENXIO)
                WARN("open %s: FIFO not yet opened for reading", ctxt->config.pcap_file);
            else
                FATAL(2, "open %s: %m", ctxt->config.pcap_file);
        }
    } else {
        ctxt->pcapng_fd = open(ctxt->config.pcap_file, O_WRONLY | O_CREAT | O_TRUNC, 0666);
        FATAL_ON(ctxt->pcapng_fd < 0, 2, "open %s: %m", ctxt->config.pcap_file);
    }

    wsbr_pcapng_write_start(ctxt);
}

static int wsbr_mac_rebuild(uint8_t frame[], mcps_data_ind_t *ind, mcps_data_ie_list_t *ie)
{
    uint8_t *start = frame;
    uint16_t fcf;
    int i;

    fcf = FIELD_PREP(IEEE802154_FCF_FRAME_TYPE,         IEEE802154_FRAME_TYPE_DATA)
        | FIELD_PREP(IEEE802154_FCF_SECURITY_ENABLED,   false)
        | FIELD_PREP(IEEE802154_FCF_FRAME_PENDING,      ind->PendingBit)
        | FIELD_PREP(IEEE802154_FCF_ACK_REQ,            ind->TxAckReq)
        | FIELD_PREP(IEEE802154_FCF_PAN_ID_COMPRESSION, ind->PanIdSuppressed)
        | FIELD_PREP(IEEE802154_FCF_SEQ_NUM_SUPPR,      ind->DSN_suppressed)
        | FIELD_PREP(IEEE802154_FCF_SEQ_IE_PRESENT,     ie->headerIeListLength || ie->payloadIeListLength)
        | FIELD_PREP(IEEE802154_FCF_DST_ADDR_MODE,      ind->DstAddrMode)
        | FIELD_PREP(IEEE802154_FCF_FRAME_VERSION,      MAC_FRAME_VERSION_2015)
        | FIELD_PREP(IEEE802154_FCF_SRC_ADDR_MODE,      ind->SrcAddrMode);
    frame = common_write_16_bit_inverse(fcf, frame);
    if (!ind->DSN_suppressed)
        *frame++ = ind->DSN;

    for (i = 0; i < ARRAY_SIZE(ieee802154_table_pan_id_comp); i++)
        if (ieee802154_table_pan_id_comp[i].dst_addr_mode      == ind->DstAddrMode &&
            ieee802154_table_pan_id_comp[i].src_addr_mode      == ind->SrcAddrMode &&
            ieee802154_table_pan_id_comp[i].pan_id_compression == ind->PanIdSuppressed)
            break;
    BUG_ON(i == ARRAY_SIZE(ieee802154_table_pan_id_comp), "invalid address mode");
    if (ieee802154_table_pan_id_comp[i].dst_pan_id)
        frame = common_write_16_bit_inverse(ind->DstPANId, frame);
    if (ind->DstAddrMode == MAC_ADDR_MODE_64_BIT) {
        memrcpy(frame, ind->DstAddr, 8);
        frame += 8;
    } else if (ind->DstAddrMode == MAC_ADDR_MODE_16_BIT) {
        memrcpy(frame, ind->DstAddr, 2);
        frame += 2;
    }
    if (ieee802154_table_pan_id_comp[i].src_pan_id)
        frame = common_write_16_bit_inverse(ind->SrcPANId, frame);
    if (ind->SrcAddrMode == MAC_ADDR_MODE_64_BIT) {
        memrcpy(frame, ind->SrcAddr, 8);
        frame += 8;
    } else if (ind->SrcAddrMode == MAC_ADDR_MODE_16_BIT) {
        memrcpy(frame, ind->SrcAddr, 2);
        frame += 2;
    }

    for (i = 0; i < ARRAY_SIZE(ieee802154_table_term_ie); i++)
        if (ieee802154_table_term_ie[i].header_ie    == (bool)ie->headerIeListLength  &&
            ieee802154_table_term_ie[i].payload_ie   == (bool)ie->payloadIeListLength &&
            ieee802154_table_term_ie[i].data_payload == (bool)ind->msduLength)
            break;
    memcpy(frame, ie->headerIeList, ie->headerIeListLength);
    frame += ie->headerIeListLength;
    if (ieee802154_table_term_ie[i].ie_ht)
        frame = common_write_16_bit_inverse(ieee802154_table_term_ie[i].ie_ht, frame);
    memcpy(frame, ie->payloadIeList, ie->payloadIeListLength);
    frame += ie->payloadIeListLength;
    if (ieee802154_table_term_ie[i].ie_pt)
        frame = common_write_16_bit_inverse(ieee802154_table_term_ie[i].ie_pt, frame);
    memcpy(frame, ind->msdu_ptr, ind->msduLength);
    frame += ind->msduLength;

    return frame - start;
}

void wsbr_pcapng_write_frame(struct wsbr_ctxt *ctxt, mcps_data_ind_t *ind, mcps_data_ie_list_t *ie)
{
    uint8_t frame[MAC_IEEE_802_15_4G_MAX_PHY_PACKET_SIZE];
    struct iobuf_write buf = { 0 };
    struct pcapng_epb epb = {
        .if_id = 0, // only one interface is used
        // ind->timestamp is in µs
        .timestamp.tv_sec  =  ind->timestamp / 1000000,
        .timestamp.tv_nsec = (ind->timestamp % 1000000) * 1000,
    };

    epb.pkt_len    = wsbr_mac_rebuild(frame, ind, ie);
    epb.pkt_len_og = epb.pkt_len;
    epb.pkt        = frame;
    pcapng_write_epb(&buf, &epb);
    wsbr_pcapng_write(ctxt, &buf);
    iobuf_free(&buf);
}
