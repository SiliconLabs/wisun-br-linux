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
#include "common/ieee802154_frame.h"
#include "common/ieee802154_ie.h"
#include "common/iobuf.h"
#include "common/pcapng.h"
#include "common/string_extra.h"
#include "common/specs/ieee802154.h"

#include "rcp_api_legacy.h"
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

void wsbr_pcapng_write_frame(struct wsbr_ctxt *ctxt, uint64_t timestamp_us,
                             const void *frame, size_t frame_len)
{
    struct iobuf_write iobuf_pcapng = { };
    struct iobuf_write iobuf_frame = { };
    struct iobuf_read ie_payload;
    struct iobuf_read ie_header;
    struct ieee802154_hdr hdr;
    int ret;

    ret = ieee802154_frame_parse(frame, frame_len, &hdr, &ie_header, &ie_payload);
    if (ret < 0)
        return;
    hdr.key_index = 0; // Strip the Auxiliary Security Header

    ieee802154_frame_write_hdr(&iobuf_frame, &hdr);
    iobuf_push_data(&iobuf_frame, ie_header.data, ie_header.data_size);
    if (ie_payload.data_size) {
        ieee802154_ie_push_header(&iobuf_frame, IEEE802154_IE_ID_HT1);
        iobuf_push_data(&iobuf_frame, ie_payload.data, ie_payload.data_size);
    }

    pcapng_write_epb(&iobuf_pcapng, timestamp_us, iobuf_frame.data, iobuf_frame.len);
    wsbr_pcapng_write(ctxt, &iobuf_pcapng);

    iobuf_free(&iobuf_pcapng);
    iobuf_free(&iobuf_frame);
}
