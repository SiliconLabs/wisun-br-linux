#define _DEFAULT_SOURCE
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include "common/log.h"
#include "wsbr.h"

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
}
