#include "app_wsbrd/libwsbrd.h"
#include "app_wsbrd/wsbr.h"
#include "common/bus_uart.h"
#include "wsbrd_fuzz.h"
#include "commandline.h"
#include "capture.h"

struct fuzz_ctxt g_fuzz_ctxt = { };

int __real_uart_rx(struct os_ctxt *ctxt, void *buf, unsigned int buf_len);
int __wrap_uart_rx(struct os_ctxt *ctxt, void *buf, unsigned int buf_len)
{
    struct fuzz_ctxt *fuzz_ctxt = &g_fuzz_ctxt;
    uint8_t frame[4096];
    size_t frame_len;

    if (!fuzz_ctxt->capture_enabled)
        return __real_uart_rx(ctxt, buf, buf_len);

    frame_len = uart_rx_hdlc(ctxt, frame, sizeof(frame));
    if (!frame_len)
        return 0;
    if (fuzz_ctxt->capture_enabled)
        fuzz_capture(fuzz_ctxt, frame, frame_len);
    frame_len = uart_decode_hdlc(buf, buf_len, frame, frame_len);
    return frame_len;
}

int main(int argc, char *argv[])
{
    struct fuzz_ctxt *ctxt = &g_fuzz_ctxt;

    argc = fuzz_parse_commandline(ctxt, argv);
    return wsbr_main(argc, argv);
}
