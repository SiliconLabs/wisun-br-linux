/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
#include "nanostack/mlme.h"

#include "bus_uart.h"
#include "wsmac_mac.h"
#include "wsmac.h"
#include "spinel.h"
#include "log.h"

static const struct {
    const char *str;
    mlme_attr_t attr;
    void (*prop_set)(struct wsmac_ctxt *ctxt, mlme_attr_t attr, const void *frame, int frame_len);
    unsigned int prop;
} mlme_prop_cstr[] = {
    { }
};

void uart_rx(struct wsmac_ctxt *ctxt)
{
    uint8_t hdr;
    int cmd, prop;
    uint8_t buf[256];
    uint8_t *data;
    int len, data_len;
    int i;

    len = wsbr_uart_rx(ctxt->os_ctxt, buf, sizeof(buf));
    spinel_datatype_unpack(buf, len, "CiiD", &hdr, &cmd, &prop, &data, &data_len);
    for (i = 0; mlme_prop_cstr[i].prop; i++)
        if (prop == mlme_prop_cstr[i].prop)
            break;

    if (cmd == SPINEL_CMD_PROP_VALUE_SET) {
        TRACE("set %s", mlme_prop_cstr[i].str);
        if (mlme_prop_cstr[i].prop_set)
            mlme_prop_cstr[i].prop_set(ctxt, mlme_prop_cstr[i].attr, data, data_len);
    } else {
        WARN("not implemented");
        return;
    }
}

void wsmac_mcps_data_confirm(const mac_api_t *mac_api, const mcps_data_conf_t *data)
{
    WARN("not implemented");
}

void wsmac_mcps_data_indication(const mac_api_t *mac_api, const mcps_data_ind_t *data)
{
    WARN("not implemented");
}

void wsmac_mcps_purge_confirm(const mac_api_t *mac_api, mcps_purge_conf_t *data)
{
    WARN("not implemented");
}

void wsmac_mlme_confirm(const mac_api_t *mac_api, mlme_primitive id, const void *data)
{
    WARN("not implemented");
}

void wsmac_mlme_indication(const mac_api_t *mac_api, mlme_primitive id, const void *data)
{
    WARN("not implemented");
}

void wsmac_mcps_data_confirm_ext(const mac_api_t *mac_api, const mcps_data_conf_t *data,
                                 const mcps_data_conf_payload_t *conf_data)
{
    WARN("not implemented");
}

void wsmac_mcps_data_indication_ext(const mac_api_t *mac_api, const mcps_data_ind_t *data,
                                    const mcps_data_ie_list_t *ie_ext)
{
    WARN("not implemented");
}

void wsmac_mcps_ack_data_req_ext(const mac_api_t *mac_api, mcps_ack_data_payload_t *data,
                                 int8_t rssi, uint8_t lqi)
{
    WARN("not implemented");
}

void wsmac_mcps_edfe_handler(const mac_api_t *mac_api, mcps_edfe_response_t *response_message)
{
    WARN("not implemented");
}
