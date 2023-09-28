#define _DEFAULT_SOURCE
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include "common/bits.h"
#include "common/endian.h"
#include "common/log.h"
#include "common/utils.h"
#include "common/iobuf.h"
#include "common/pcapng.h"
#include "common/string_extra.h"

#include "frame_helpers.h"
#include "wsbr.h"

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
    struct iobuf_write buf = { };

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
            FATAL(2, "stat %s: %m", ctxt->config.pcap_file);
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

void wsbr_pcapng_write_frame(struct wsbr_ctxt *ctxt, mcps_data_ind_t *ind, mcps_data_ie_list_t *ie)
{
    uint8_t frame[MAC_IEEE_802_15_4G_MAX_PHY_PACKET_SIZE];
    struct iobuf_write buf = { };
    struct pcapng_epb epb = {
        .if_id = 0, // only one interface is used
        .timestamp = ind->timestamp, // ind->timestamp is in us
    };

    epb.pkt_len    = wsbr_data_ind_rebuild(frame, ind, ie);
    epb.pkt_len_og = epb.pkt_len;
    epb.pkt        = frame;
    pcapng_write_epb(&buf, &epb);
    wsbr_pcapng_write(ctxt, &buf);
    iobuf_free(&buf);
}
