#define _DEFAULT_SOURCE
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include "common/log.h"
#include "common/pcapng.h"
#include "wsbr.h"

static void wsbr_pcapng_write(struct wsbr_ctxt *ctxt, const struct pcapng_buf *buf)
{
    int ret;

    ret = write(ctxt->pcapng_fd, buf->buf, buf->cnt);
    if (ret < 0 && !(ret == -EAGAIN && ctxt->pcapng_type == S_IFIFO))
        FATAL(2, "write pcapng: %m");
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
    struct pcapng_buf *buf = ALLOC_STACK_PCAPNG_BUF(
        PCAPNG_SHB_SIZE_MIN + PCAPNG_IDB_SIZE_MIN
    );

    pcapng_write_shb(buf, &shb);
    pcapng_write_idb(buf, &idb);
    wsbr_pcapng_write(ctxt, buf);
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
