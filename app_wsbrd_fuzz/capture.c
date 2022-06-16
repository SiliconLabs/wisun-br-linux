#include <unistd.h>

#include "common/log.h"
#include "wsbrd_fuzz.h"
#include "capture.h"

void fuzz_capture(struct fuzz_ctxt *ctxt, const void *data, size_t size)
{
    int ret;

    ret = write(ctxt->uart_fd, data, size);
    FATAL_ON(ret < 0, 2, "write: %m");
    FATAL_ON(ret < size, 2, "write: Short write");
}
