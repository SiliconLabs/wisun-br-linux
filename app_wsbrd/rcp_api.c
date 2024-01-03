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
#include "common/bits.h"
#include "common/hif.h"
#include "common/iobuf.h"
#include "common/log.h"
#include "common/memutils.h"
#include "common/spinel.h"
#include "common/string_extra.h"
#include "common/version.h"
#include "common/ws_regdb.h"
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

static void __rcp_set_host_api(struct rcp *rcp, uint32_t host_api_version)
{
    struct iobuf_write buf = { };

    hif_push_u8(&buf, HIF_CMD_SET_HOST_API);
    hif_push_u32(&buf, host_api_version);
    rcp_tx(rcp, &buf);
    iobuf_free(&buf);
}

void rcp_set_host_api(struct rcp *rcp, uint32_t host_api_version)
{
    if (!version_older_than(rcp->version_api, 2, 0, 0))
        __rcp_set_host_api(rcp, host_api_version);
}

static void __rcp_req_radio_list(struct rcp *rcp)
{
    struct iobuf_write buf = { };

    hif_push_u8(&buf, HIF_CMD_REQ_RADIO_LIST);
    rcp_tx(rcp, &buf);
    iobuf_free(&buf);
}

void rcp_req_radio_list(struct rcp *rcp)
{
    if (version_older_than(rcp->version_api, 2, 0, 0))
        rcp_legacy_get_rf_config_list();
    else
        __rcp_req_radio_list(rcp);
}

#define HIF_MASK_RADIO_LIST_GROUP 0x0001
#define HIF_MASK_RADIO_LIST_MCS   0x01fe

static void rcp_cnf_radio_list(struct rcp *rcp, struct iobuf_read *buf)
{
    const struct phy_params *phy_params;
    bool group_bit, group_bit_prev, list_end;
    int phy_mode_group = 0;
    uint8_t entry_size;
    uint16_t flags;
    int offset;
    int i = 0;

    BUG_ON(rcp->init_state & RCP_HAS_RF_CONFIG_LIST);
    entry_size = hif_pop_u8(buf);
    BUG_ON(entry_size < 2 + 1 + 4 + 4 + 2);
    list_end   = hif_pop_bool(buf);
    if (rcp->rail_config_list)
        while (rcp->rail_config_list[i].chan0_freq)
            i++;
    group_bit_prev = true;
    while (iobuf_remaining_size(buf)) {
        rcp->rail_config_list = reallocarray(rcp->rail_config_list, i + 2, sizeof(struct rcp_rail_config));
        offset = buf->cnt;
        flags = hif_pop_u16(buf);
        rcp->rail_config_list[i].index = i;
        rcp->rail_config_list[i].rail_phy_mode_id = hif_pop_u8(buf);
        rcp->rail_config_list[i].chan0_freq       = hif_pop_u32(buf);
        rcp->rail_config_list[i].chan_spacing     = hif_pop_u32(buf);
        rcp->rail_config_list[i].chan_count       = hif_pop_u16(buf);
        if (buf->cnt - offset < entry_size)
            hif_pop_fixed_u8_array(buf, NULL, entry_size - (buf->cnt - offset));
        phy_params = ws_regdb_phy_params(rcp->rail_config_list[i].rail_phy_mode_id, 0);
        if (phy_params && phy_params->modulation == MODULATION_OFDM &&
            FIELD_GET(HIF_MASK_RADIO_LIST_MCS, flags) != 0x00ff)
            BUG("unsupported OFDM PHY with MCS support not 0-7");
        group_bit = FIELD_GET(HIF_MASK_RADIO_LIST_GROUP, flags);
        BUG_ON(i == 0 && group_bit);
        if (group_bit && !group_bit_prev)
            rcp->rail_config_list[i - 1].phy_mode_group = ++phy_mode_group;
        rcp->rail_config_list[i].phy_mode_group = group_bit ? phy_mode_group : 0;
        group_bit_prev = group_bit;
        i++;
    }
    memset(&rcp->rail_config_list[i], 0, sizeof(struct rcp_rail_config));
    BUG_ON(buf->err || iobuf_remaining_size(buf));
    if (list_end)
        rcp->init_state |= RCP_HAS_RF_CONFIG_LIST;
}

static void __rcp_set_radio(struct rcp *rcp, uint8_t radioconf_index, uint8_t ofdm_mcs, bool enable_ms)
{
    struct iobuf_write buf = { };

    hif_push_u8(&buf, HIF_CMD_SET_RADIO);
    hif_push_u8(&buf, radioconf_index);
    hif_push_u8(&buf, ofdm_mcs);
    hif_push_bool(&buf, enable_ms);
    rcp_tx(rcp, &buf);
    iobuf_free(&buf);

    rcp->init_state |= RCP_HAS_RF_CONFIG;
}

void rcp_set_radio(struct rcp *rcp, const struct phy_rf_channel_configuration *rf_config)
{
    if (version_older_than(rcp->version_api, 0, 25, 1))
        rcp_legacy_set_rf_config_legacy(rf_config);
    else if (version_older_than(rcp->version_api, 2, 0, 0))
        rcp_legacy_set_rf_config(rf_config);
    else
        __rcp_set_radio(rcp,
                        rf_config->rcp_config_index,
                        rf_config->ofdm_mcs,
                        rf_config->use_phy_op_modes);
}

static void __rcp_set_radio_regulation(struct rcp *rcp, enum hif_reg reg)
{
    struct iobuf_write buf = { };

    hif_push_u8(&buf, HIF_CMD_SET_RADIO_REGULATION);
    hif_push_u8(&buf, reg);
    rcp_tx(rcp, &buf);
    iobuf_free(&buf);
}

void rcp_set_radio_regulation(struct rcp *rcp, enum hif_reg reg)
{
    if (version_older_than(rcp->version_api, 2, 0, 0)) {
        if (reg == HIF_REG_ARIB)
            rcp_legacy_set_regional_regulation(REG_REGIONAL_ARIB);
        else if (reg == HIF_REG_NONE)
            rcp_legacy_set_regional_regulation(REG_REGIONAL_NONE);
        else
            rcp_legacy_set_regional_regulation(REG_REGIONAL_UNDEF);
        rcp_legacy_set_edfe_mode(reg != HIF_REG_ARIB);
    } else {
        __rcp_set_radio_regulation(rcp, reg);
    }
}

static void __rcp_set_sec_key(struct rcp *rcp,
                              uint8_t key_index,
                              const uint8_t key[16],
                              uint32_t frame_counter)
{
    struct iobuf_write buf = { };

    hif_push_u8(&buf, HIF_CMD_SET_SEC_KEY);
    hif_push_u8(&buf, key_index);
    hif_push_fixed_u8_array(&buf, key ? : (uint8_t[16]){ }, 16);
    hif_push_u32(&buf, frame_counter);
    rcp_tx(rcp, &buf);
    iobuf_free(&buf);
}

void rcp_set_sec_key(struct rcp *rcp,
                     uint8_t key_index,
                     const uint8_t key[16],
                     uint32_t frame_counter)
{
    const uint8_t lookup_data[9] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, key_index
    };

    BUG_ON(key_index < 1 || key_index > 7);
    if (version_older_than(rcp->version_api, 2, 0, 0)) {
        rcp_legacy_set_key(key_index - 1, lookup_data, key);
        if (key && !memzcmp(key, 16))
            rcp_legacy_set_frame_counter(key_index - 1, frame_counter);
    } else {
        __rcp_set_sec_key(rcp, key_index, key, frame_counter);
    }
}

static const struct {
    uint8_t cmd;
    void (*fn)(struct rcp *rcp, struct iobuf_read *buf);
} rcp_cmd_table[] = {
    { HIF_CMD_IND_RESET,      rcp_ind_reset      },
    { HIF_CMD_IND_FATAL,      rcp_ind_fatal      },
    { HIF_CMD_CNF_RADIO_LIST, rcp_cnf_radio_list },
    { 0xff,                   rcp_ind_legacy     },
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
