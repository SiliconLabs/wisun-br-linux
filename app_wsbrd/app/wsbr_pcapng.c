/*
 * Copyright (c) 2024 Silicon Laboratories Inc. (www.silabs.com)
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
#define _DEFAULT_SOURCE
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include "common/bits.h"
#include "common/endian.h"
#include "common/log.h"
#include "common/memutils.h"
#include "common/iobuf.h"
#include "common/pcapng.h"
#include "common/string_extra.h"
#include "common/specs/ieee802154.h"

#include "rcp_api_legacy.h"
#include "frame_helpers.h"
#include "wsbrd.h"

void wsbr_pcapng_closed(struct wsbr_ctxt *ctxt)
{
    int ret;

    WARN("stopped pcapng capture");
    ret = close(ctxt->pcapng_fd);
    FATAL_ON(ret < 0, 2, "close pcapng: %m");
    ctxt->pcapng_fd = -1;
    ctxt->fds[POLLFD_PCAP].fd = -1;
}

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
        ctxt->fds[POLLFD_PCAP].fd = ctxt->pcapng_fd;
        wsbr_pcapng_write_start(ctxt);
    }

    ret = write(ctxt->pcapng_fd, buf->data, buf->len);
    if (ret >= 0)
        return;
    if (ctxt->pcapng_type == S_IFIFO && errno == EAGAIN)
        WARN("pcapng fifo full");
    else
        FATAL(2, "write pcapng: %m");
}

static void wsbr_pcapng_write_start(struct wsbr_ctxt *ctxt)
{
    struct iobuf_write buf = { };

    pcapng_write_shb(&buf);
    pcapng_write_idb(&buf, LINKTYPE_IEEE802_15_4_NOFCS);
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

    ctxt->fds[POLLFD_PCAP].fd = ctxt->pcapng_fd;
    wsbr_pcapng_write_start(ctxt);
}

void wsbr_pcapng_write_frame(struct wsbr_ctxt *ctxt, mcps_data_ind_t *ind,
                             struct mcps_data_rx_ie_list *ie)
{
    uint8_t frame[MAC_IEEE_802_15_4G_MAX_PHY_PACKET_SIZE];
    struct iobuf_write buf = { };
    size_t frame_len;

    frame_len = wsbr_data_ind_rebuild(frame, ind, ie);
    pcapng_write_epb(&buf, ind->hif.timestamp_us, frame, frame_len);
    wsbr_pcapng_write(ctxt, &buf);
    iobuf_free(&buf);
}
