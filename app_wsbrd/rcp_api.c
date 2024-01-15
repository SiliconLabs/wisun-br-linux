/*
 * Copyright (c) 2023 Silicon Laboratories Inc. (www.silabs.com)
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
#include "app_wsbrd/wsbr.h"
#include "app_wsbrd/rcp_api_legacy.h"
#include "common/hif.h"
#include "common/iobuf.h"
#include "common/log.h"
#include "common/memutils.h"
#include "common/spinel.h"
#include "common/version.h"
#include "rcp_api.h"

uint8_t rcp_rx_buf[4096];

static void rcp_tx(struct rcp *rcp, struct iobuf_write *buf)
{
    struct wsbr_ctxt *ctxt = container_of(rcp, struct wsbr_ctxt, rcp);

    BUG_ON(!buf->len);
    TRACE(TR_HIF, "hif tx: %s %s", hif_cmd_str(buf->data[0]),
          tr_bytes(buf->data + 1, buf->len - 1,
                   NULL, 128, DELIM_SPACE | ELLIPSIS_STAR));
    rcp->device_tx(ctxt->os_ctxt, buf->data, buf->len);
}

void rcp_req_reset(struct rcp *rcp, bool bootload)
{
    struct iobuf_write buf = { };

    hif_push_u8(&buf, HIF_CMD_REQ_RESET);
    hif_push_bool(&buf, bootload);
    rcp_tx(rcp, &buf);
    iobuf_free(&buf);
}

static void rcp_ind_reset(struct rcp *rcp, struct iobuf_read *buf)
{
    const char *version_label;

    FATAL_ON(rcp->init_state & RCP_HAS_RESET, 3, "unsupported RCP reset");

    rcp->version_api = hif_pop_u32(buf);
    rcp->version_fw  = hif_pop_u32(buf);
    version_label    = hif_pop_str(buf);
    hif_pop_fixed_u8_array(buf, rcp->eui64, 8);
    BUG_ON(buf->err);

    BUG_ON(version_older_than(rcp->version_api, 2, 0, 0));
    rcp->version_label = strdup(version_label);
    BUG_ON(!rcp->version_label);
    rcp->init_state |= RCP_HAS_RESET;
    rcp->init_state |= RCP_HAS_HWADDR;
}

static void rcp_ind_fatal(struct rcp *rcp, struct iobuf_read *buf)
{
    const char *msg;
    uint8_t err;

    err = hif_pop_u8(buf);
    msg = hif_pop_str(buf);
    BUG_ON(buf->err);

    if (msg)
        FATAL(3, "rcp error 0x%02x: %s", err, msg);
    else
        FATAL(3, "rcp error 0x%02x", err);
}

static const struct {
    uint8_t cmd;
    void (*fn)(struct rcp *rcp, struct iobuf_read *buf);
} rcp_cmd_table[] = {
    { HIF_CMD_IND_RESET, rcp_ind_reset  },
    { HIF_CMD_IND_FATAL, rcp_ind_fatal  },
    { 0xff,              rcp_ind_legacy },
};

void rcp_rx(struct rcp *rcp)
{
    struct wsbr_ctxt *ctxt = container_of(rcp, struct wsbr_ctxt, rcp);
    struct iobuf_read buf = { .data = rcp_rx_buf };
    uint32_t cmd;

    if (version_older_than(rcp->version_api, 2, 0, 0)) {
        rcp_legacy_rx(ctxt);
        return;
    }

    buf.data_size = rcp->device_rx(ctxt->os_ctxt, rcp_rx_buf, sizeof(rcp_rx_buf));
    if (!buf.data_size)
        return;
    cmd = hif_pop_u8(&buf);
    if (cmd == 0xff)
        spinel_trace(buf.data, buf.data_size, "hif rx: ");
    else
        TRACE(TR_HIF, "hif rx: %s %s", hif_cmd_str(cmd),
              tr_bytes(iobuf_ptr(&buf), iobuf_remaining_size(&buf),
                       NULL, 128, DELIM_SPACE | ELLIPSIS_STAR));
    for (int i = 0; i < ARRAY_SIZE(rcp_cmd_table); i++)
        if (rcp_cmd_table[i].cmd == cmd)
            return rcp_cmd_table[i].fn(rcp, &buf);
    TRACE(TR_DROP, "drop %-9s: unsupported command 0x%02x", "hif", cmd);
}
