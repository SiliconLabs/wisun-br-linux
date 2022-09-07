#include <stdint.h>
#include <unistd.h>

#include "app_wsbrd/wsbr.h"
#include "app_wsbrd/wsbr_mac.h"
#include "common/log.h"
#include "common/spinel_buffer.h"
#include "interfaces.h"
#include "wsbrd_fuzz.h"
#include "capture.h"

void __wrap_wsbr_spinel_replay_interface(struct spinel_buffer *buf)
{
    uint8_t interface;
    uint8_t *data;
    size_t size;
    int ret;

    FATAL_ON(!(g_ctxt.rcp_init_state & RCP_INIT_DONE), 1, "interface command received during RCP init");
    FATAL_ON(!g_fuzz_ctxt.replay_count, 1, "interface command received while replay is disabled");

    interface = spinel_pop_u8(buf);
    if (buf->err)
        return;

    if (interface != IF_TUN)
        return;

    size = spinel_pop_data_ptr(buf, &data);
    ret = write(g_fuzz_ctxt.tun_pipe[1], data, size);
    FATAL_ON(ret < 0, 2, "write: %m");
    FATAL_ON(ret < size, 2, "write: Short write");
}
