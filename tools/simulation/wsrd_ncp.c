/*
 * SPDX-License-Identifier: LicenseRef-MSLA
 * Copyright (c) 2025 Silicon Laboratories Inc. (www.silabs.com)
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
#include <ns3/sl-wisun-linux.h>
#include <sl_wisun_msg_api.h>
#include <sl_wisun_version.h>
#include <endian.h>
#include <pthread.h>

#include "app_wsrd/app/wsrd.h"
#include "common/ipv6/ipv6_addr.h"
#include "common/log.h"
#include "common/string_extra.h"
#include "tools/simulation/ncp_ind.h"
#include "tools/simulation/ncp_socket.h"
#include "tools/simulation/ncp_values.h"

static bool g_has_thread;
static pthread_t g_thread;

static void *ncp_main(void *arg)
{
    struct wsrd_conf *cfg = arg;

    // Provide a UART device so parse_commandline succeeds
    strcpy(cfg->rcp_cfg.uart_dev, "/dev/null");
    cfg->storage_delete = true;
    wsrd_main(3, (char *[]){ "wsrd", "-F", g_config_filename, NULL });
    __builtin_unreachable();
}

__attribute__((destructor))
static void ncp_exit(void)
{
    if (g_has_thread) {
        pthread_cancel(g_thread);
        pthread_join(g_thread, NULL);
    }
}

static void ncp_join(const void *_req, const void *req_data, void *_cnf, void *cnf_data)
{
    static const int phy_config_sizes[] = {
        [SL_WISUN_PHY_CONFIG_FAN10]    = sizeof(sl_wisun_phy_config_fan10_t),
        [SL_WISUN_PHY_CONFIG_FAN11]    = sizeof(sl_wisun_phy_config_fan11_t),
        [SL_WISUN_PHY_CONFIG_EXPLICIT] = sizeof(sl_wisun_phy_config_explicit_t),
    };
    static const uint32_t chan_spacings[] = {
        [SL_WISUN_CHANNEL_SPACING_100KHZ]  =  100000,
        [SL_WISUN_CHANNEL_SPACING_200KHZ]  =  200000,
        [SL_WISUN_CHANNEL_SPACING_400KHZ]  =  400000,
        [SL_WISUN_CHANNEL_SPACING_600KHZ]  =  600000,
        [SL_WISUN_CHANNEL_SPACING_250KHZ]  =  250000,
        [SL_WISUN_CHANNEL_SPACING_800KHZ]  =  800000,
        [SL_WISUN_CHANNEL_SPACING_1200KHZ] = 1200000,
    };
    const sl_wisun_msg_join_req_t *req = _req;
    struct wsrd_conf *cfg = &g_wsrd.config;
    sl_wisun_msg_join_cnf_t *cnf = _cnf;
    int ret;

    if (g_has_thread) {
        cnf->body.status = htole32(SL_STATUS_NETWORK_UP);
        return;
    }

    cfg->ws_domain = REG_DOMAIN_UNDEF;
    cfg->ws_mode = 0;
    cfg->ws_class = 0;
    cfg->ws_phy_mode_id = 0;
    cfg->ws_chan_plan_id = 0;
    cfg->ws_chan0_freq = 0;
    cfg->ws_chan_count = 0;
    cfg->ws_chan_spacing = 0;

    if (le32toh(req->body.phy_config.type) >= ARRAY_SIZE(phy_config_sizes) ||
        !phy_config_sizes[le32toh(req->body.phy_config.type)]) {
        WARN("unsupported NCP JOIN phy-type=%u", req->body.phy_config.type);
        cnf->body.status = htole32(SL_STATUS_NOT_SUPPORTED);
        return;
    }

    if (le16toh(req->header.length) < sizeof(*req) - sizeof(req->body.phy_config) +
                                      phy_config_sizes[le32toh(req->body.phy_config.type)])
        FATAL(3, "malformed NCP JOIN len=%u phy-type=%u", req->header.length, req->body.phy_config.type);

    switch (req->body.phy_config.type) {
    case SL_WISUN_PHY_CONFIG_FAN10:
        cfg->ws_domain = req->body.phy_config.config.fan10.reg_domain;
        cfg->ws_mode   = req->body.phy_config.config.fan10.op_mode;
        cfg->ws_class  = req->body.phy_config.config.fan10.op_class;
        if (req->body.phy_config.config.fan10.fec) {
            WARN("unsupported phy config fan10 fec");
            cnf->body.status = htole32(SL_STATUS_NOT_SUPPORTED);
            return;
        }
        break;
    case SL_WISUN_PHY_CONFIG_FAN11:
        cfg->ws_domain       = req->body.phy_config.config.fan11.reg_domain;
        cfg->ws_phy_mode_id  = req->body.phy_config.config.fan11.phy_mode_id;
        cfg->ws_chan_plan_id = req->body.phy_config.config.fan11.chan_plan_id;
        break;
    case SL_WISUN_PHY_CONFIG_EXPLICIT:
        cfg->ws_chan0_freq   = le32toh(req->body.phy_config.config.explicit_plan.ch0_frequency_khz) * 1000;
        cfg->ws_chan_count   = le16toh(req->body.phy_config.config.explicit_plan.number_of_channels);
        if (req->body.phy_config.config.explicit_plan.channel_spacing >= ARRAY_SIZE(chan_spacings)) {
            WARN("unsupported phy config explicit spacing=%u",
                 req->body.phy_config.config.explicit_plan.channel_spacing);
            cnf->body.status = htole32(SL_STATUS_NOT_SUPPORTED);
            return;
        }
        cfg->ws_chan_spacing = chan_spacings[req->body.phy_config.config.explicit_plan.channel_spacing];
        cfg->ws_phy_mode_id  = req->body.phy_config.config.fan11.phy_mode_id;
        break;
    }

    memcpy(cfg->ws_netname, req->body.name, WS_NETNAME_LEN);
    cfg->ws_netname[WS_NETNAME_LEN - 1] = '\0';

    ret = pthread_create(&g_thread, NULL, ncp_main, cfg);
    if (ret) {
        WARN("pthread_create: %s", strerror(ret));
        cnf->body.status = htole32(ncp_status(ret));
        return;
    }
    g_has_thread = true;
}

static void ncp_set_regulation(const void *_req, const void *req_data, void *_cnf, void *cnf_data)
{
    static const struct ncp_val regulations[] = {
        { SL_WISUN_REGULATION_NONE, HIF_REG_NONE },
        { SL_WISUN_REGULATION_ARIB, HIF_REG_ARIB },
        { SL_WISUN_REGULATION_WPC,  HIF_REG_WPC },
    };
    const sl_wisun_msg_set_regulation_req_t *req = _req;
    sl_wisun_msg_set_regulation_cnf_t *cnf = _cnf;
    int regulation;

    regulation = ncp_ntoh(le32toh(req->body.regulation), regulations, ARRAY_SIZE(regulations));

    // FIXME: wsrd does not support regional regulation yet
    if (regulation != HIF_REG_NONE)
        cnf->body.status = htole32(SL_STATUS_NOT_SUPPORTED);
}

static void ncp_set_txpow(const void *_req, const void *req_data, void *cnf, void *cnf_data)
{
    const sl_wisun_msg_set_tx_power_req_t *req = _req;
    struct wsrd *wsrd = &g_wsrd;

    wsrd->config.tx_power = req->body.tx_power;
}

static void ncp_set_txpow_ddbm(const void *_req, const void *req_data, void *_cnf, void *cnf_data)
{
    const sl_wisun_msg_set_tx_power_ddbm_req_t *req = _req;
    sl_wisun_msg_set_tx_power_ddbm_cnf_t *cnf = _cnf;
    struct wsrd *wsrd = &g_wsrd;
    int16_t txpow_ddbm;

    txpow_ddbm = (int16_t)le16toh(req->body.tx_power_ddbm);

    // TODO: support ddBm
    if (txpow_ddbm % 10) {
        cnf->body.status = htole32(SL_STATUS_NOT_SUPPORTED);
        return;
    }

    wsrd->config.tx_power = txpow_ddbm / 10;
}

static sl_status_t ncp_set_pem(struct iovec *out, const char *buf, size_t buf_len, bool append)
{
    if (!buf_len || buf[buf_len - 1] != '\0')
        return SL_STATUS_INVALID_PARAMETER;

    if (append) {
        ((char *)out->iov_base)[out->iov_len - 1] = '\n';
        out->iov_base = realloc(out->iov_base, out->iov_len + buf_len);
        if (!out->iov_base)
            return SL_STATUS_ALLOCATION_FAILED;
        FATAL_ON(!out->iov_base, 2);
        memcpy((char *)out->iov_base + out->iov_len, buf, buf_len);
        out->iov_len += buf_len;
    } else {
        out->iov_base = realloc(out->iov_base, buf_len);
        if (!out->iov_base)
            return SL_STATUS_ALLOCATION_FAILED;
        memcpy(out->iov_base, buf, buf_len);
        out->iov_len = buf_len;
    }

    return SL_STATUS_OK;
}

static void ncp_set_ca(const void *_req, const void *req_data, void *_cnf, void *cnf_data)
{
    const sl_wisun_msg_set_trusted_certificate_req_t *req = _req;
    sl_wisun_msg_set_trusted_certificate_cnf_t *cnf = _cnf;

    cnf->body.status = htole32(ncp_set_pem(&g_wsrd.config.supp_cfg.tls.ca_cert, req_data,
                                           req->body.certificate_length,
                                           req->body.certificate_options & SL_WISUN_CERTIFICATE_OPTION_APPEND));
}

static void ncp_set_cert(const void *_req, const void *req_data, void *_cnf, void *cnf_data)
{
    const sl_wisun_msg_set_device_certificate_req_t *req = _req;
    sl_wisun_msg_set_device_certificate_cnf_t *cnf = _cnf;

    cnf->body.status = htole32(ncp_set_pem(&g_wsrd.config.supp_cfg.tls.cert, req_data,
                                           req->body.certificate_length, false));
}

static void ncp_set_key(const void *_req, const void *req_data, void *_cnf, void *cnf_data)
{
    const sl_wisun_msg_set_device_private_key_req_t *req = _req;
    sl_wisun_msg_set_device_private_key_cnf_t *cnf = _cnf;

    cnf->body.status = htole32(ncp_set_pem(&g_wsrd.config.supp_cfg.tls.key, req_data,
                                           req->body.key_length, false));
}

static void __ncp_set_conparams(const sl_wisun_connection_params_t *params)
{
    struct wsrd *wsrd = &g_wsrd;

    wsrd->config.disc_cfg.Imin_ms = le16toh(params->discovery.trickle_pa.imin_s) * 1000;
    wsrd->config.disc_cfg.Imax_ms = le16toh(params->discovery.trickle_pa.imax_s) * 1000;
    // TODO: other params
}

static void ncp_set_conparams(const void *_req, const void *req_data, void *cnf, void *cnf_data)
{
    const sl_wisun_msg_set_connection_params_req_t *req = _req;

    __ncp_set_conparams(&req->body.parameters);
}

static void ncp_set_netsize(const void *_req, const void *req_data, void *_cnf, void *cnf_data)
{
    static const sl_wisun_connection_params_t *profiles[] = {
        [SL_WISUN_NETWORK_SIZE_SMALL]         = &SL_WISUN_PARAMS_PROFILE_SMALL,
        [SL_WISUN_NETWORK_SIZE_MEDIUM]        = &SL_WISUN_PARAMS_PROFILE_MEDIUM,
        [SL_WISUN_NETWORK_SIZE_LARGE]         = &SL_WISUN_PARAMS_PROFILE_LARGE,
        [SL_WISUN_NETWORK_SIZE_TEST]          = &SL_WISUN_PARAMS_PROFILE_TEST,
        [SL_WISUN_NETWORK_SIZE_CERTIFICATION] = &SL_WISUN_PARAMS_PROFILE_CERTIF,
    };
    const sl_wisun_msg_set_network_size_req_t *req = _req;
    sl_wisun_msg_set_network_size_cnf_t *cnf = _cnf;

    if (req->body.size >= ARRAY_SIZE(profiles) || !profiles[req->body.size]) {
        cnf->body.status = htole32(SL_STATUS_NOT_SUPPORTED);
        return;
    }

    __ncp_set_conparams(profiles[req->body.size]);
}

static void ncp_set_devtype(const void *_req, const void *req_data, void *_cnf, void *cnf_data)
{
    const sl_wisun_msg_set_device_type_req_t *req = _req;
    sl_wisun_msg_set_device_type_cnf_t *cnf = _cnf;

    if (req->body.type != SL_WISUN_ROUTER)
        cnf->body.status = htole32(SL_STATUS_NOT_SUPPORTED);
}

static void ncp_set_lfn_support(const void *_req, const void *req_data, void *_cnf, void *cnf_data)
{
    const sl_wisun_msg_set_lfn_support_req_t *req = _req;
    sl_wisun_msg_set_lfn_support_cnf_t *cnf = _cnf;

    if (req->body.lfn_limit)
        cnf->body.status = htole32(SL_STATUS_NOT_SUPPORTED);
}

static void ncp_get_version(const void *req, const void *req_data, void *_cnf, void *cnf_data)
{
    sl_wisun_msg_get_stack_version_cnf_t *cnf = _cnf;

    // FIXME: consider wsrd version and RCP version
    cnf->body.major = SL_WISUN_VERSION_MAJOR;
    cnf->body.minor = SL_WISUN_VERSION_MINOR;
    cnf->body.patch = SL_WISUN_VERSION_PATCH;
    cnf->body.build = htole16(SL_WISUN_VERSION_BUILD);
}

static void ncp_get_ip_addr(const void *_req, const void *req_data, void *_cnf, void *cnf_data)
{
    const sl_wisun_msg_get_ip_address_req_t *req = _req;
    sl_wisun_msg_get_ip_address_cnf_t *cnf = _cnf;
    struct wsrd *wsrd = &g_wsrd;
    struct ipv6_neigh *parent;

    cnf->body.address = in6addr_any;

    switch (le32toh(req->body.address_type)) {
    case SL_WISUN_IP_ADDRESS_TYPE_LINK_LOCAL:
        cnf->body.address = ipv6_prefix_linklocal;
        ipv6_addr_conv_iid_eui64(cnf->body.address.s6_addr + 8, wsrd->ws.rcp.eui64.u8);
        break;
    case SL_WISUN_IP_ADDRESS_TYPE_GLOBAL:
        cnf->body.address = wsrd->ipv6.dhcp.iaaddr.ipv6;
        break;
    case SL_WISUN_IP_ADDRESS_TYPE_BORDER_ROUTER:
        parent = rpl_neigh_pref_parent(&wsrd->ipv6);
        if (parent)
            cnf->body.address = parent->rpl->dio.dodag_id;
        break;
    case SL_WISUN_IP_ADDRESS_TYPE_PRIMARY_PARENT:
        parent = rpl_neigh_pref_parent(&wsrd->ipv6);
        if (parent)
            cnf->body.address = parent->gua;
        break;
    }

    if (!memzcmp(cnf->body.address.s6_addr, 16))
        cnf->body.status = htole32(SL_STATUS_NOT_FOUND);
}

static uint32_t ncp_join_state(void)
{
    struct wsrd *wsrd = &g_wsrd;
    struct ipv6_neigh *parent;

    if (!g_has_thread)
        return SL_WISUN_JOIN_STATE_DISCONNECTED;
    switch (wsrd->state) {
    case WSRD_STATE_DISCOVERY:
        return SL_WISUN_JOIN_STATE_SELECT_PAN;
    case WSRD_STATE_AUTHENTICATE:
        return SL_WISUN_JOIN_STATE_AUTHENTICATE;
    case WSRD_STATE_CONFIGURE:
    case WSRD_STATE_RECONNECT:
        return SL_WISUN_JOIN_STATE_ACQUIRE_PAN_CONFIG;
    case WSRD_STATE_RPL_PARENT:
        return SL_WISUN_JOIN_STATE_PARENT_SELECT;
    case WSRD_STATE_ROUTING:
        parent = rpl_neigh_pref_parent(&wsrd->ipv6);
        BUG_ON(!parent || !parent->rpl);
        if (IN6_IS_ADDR_UNSPECIFIED(&wsrd->ipv6.dhcp.iaaddr.ipv6))
            return SL_WISUN_JOIN_STATE_DHCP;
        else if (rfc8415_txalg_stopped(&wsrd->ipv6.rpl.dao_txalg))
            return SL_WISUN_JOIN_STATE_EARO;
        else
            return SL_WISUN_JOIN_STATE_DAO;
    case WSRD_STATE_OPERATIONAL:
        return SL_WISUN_JOIN_STATE_OPERATIONAL;
    case WSRD_STATE_DISCONNECTING:
        return SL_WISUN_JOIN_STATE_DISCONNECTING;
    default:
        BUG();
    }
}

static void ncp_get_join_state(const void *req, const void *req_data, void *_cnf, void *cnf_data)
{
    sl_wisun_msg_get_join_state_cnf_t *cnf = _cnf;

    cnf->body.join_state = htole32(ncp_join_state());
}

void ns3_ncp_recv(const void *_req, const void *req_data, void *_cnf, void *cnf_data)
{
    static const struct {
        void (*func)(const void *, const void *, void *, void *);
        uint16_t req_len;
        uint8_t  cnf_id;
        uint16_t cnf_len;
    } table[] = {
        [SL_WISUN_MSG_SET_NETWORK_SIZE_REQ_ID]               = { ncp_set_netsize,   sizeof(sl_wisun_msg_set_network_size_req_t),               SL_WISUN_MSG_SET_NETWORK_SIZE_CNF_ID,               sizeof(sl_wisun_msg_set_network_size_cnf_t) },
        [SL_WISUN_MSG_GET_IP_ADDRESS_REQ_ID]                 = { ncp_get_ip_addr,   sizeof(sl_wisun_msg_get_ip_address_req_t),                 SL_WISUN_MSG_GET_IP_ADDRESS_CNF_ID,                 sizeof(sl_wisun_msg_get_ip_address_cnf_t) },
        [SL_WISUN_MSG_OPEN_SOCKET_REQ_ID]                    = { ncp_sk_open,       sizeof(sl_wisun_msg_open_socket_req_t),                    SL_WISUN_MSG_OPEN_SOCKET_CNF_ID,                    sizeof(sl_wisun_msg_open_socket_cnf_t) },
        [SL_WISUN_MSG_CLOSE_SOCKET_REQ_ID]                   = { ncp_sk_close,      sizeof(sl_wisun_msg_close_socket_req_t),                   SL_WISUN_MSG_CLOSE_SOCKET_CNF_ID,                   sizeof(sl_wisun_msg_close_socket_cnf_t) },
        [SL_WISUN_MSG_SENDTO_ON_SOCKET_REQ_ID]               = { NULL,              sizeof(sl_wisun_msg_sendto_on_socket_req_t),               SL_WISUN_MSG_SENDTO_ON_SOCKET_CNF_ID,               sizeof(sl_wisun_msg_sendto_on_socket_cnf_t) },
        [SL_WISUN_MSG_LISTEN_ON_SOCKET_REQ_ID]               = { NULL,              sizeof(sl_wisun_msg_listen_on_socket_req_t),               SL_WISUN_MSG_LISTEN_ON_SOCKET_CNF_ID,               sizeof(sl_wisun_msg_listen_on_socket_cnf_t) },
        [SL_WISUN_MSG_ACCEPT_ON_SOCKET_REQ_ID]               = { NULL,              sizeof(sl_wisun_msg_accept_on_socket_req_t),               SL_WISUN_MSG_ACCEPT_ON_SOCKET_CNF_ID,               sizeof(sl_wisun_msg_accept_on_socket_cnf_t) },
        [SL_WISUN_MSG_CONNECT_SOCKET_REQ_ID]                 = { NULL,              sizeof(sl_wisun_msg_connect_socket_req_t),                 SL_WISUN_MSG_CONNECT_SOCKET_CNF_ID,                 sizeof(sl_wisun_msg_connect_socket_cnf_t) },
        [SL_WISUN_MSG_BIND_SOCKET_REQ_ID]                    = { ncp_sk_bind,       sizeof(sl_wisun_msg_bind_socket_req_t),                    SL_WISUN_MSG_BIND_SOCKET_CNF_ID,                    sizeof(sl_wisun_msg_bind_socket_cnf_t) },
        [SL_WISUN_MSG_SEND_ON_SOCKET_REQ_ID]                 = { ncp_sk_send,       sizeof(sl_wisun_msg_send_on_socket_req_t),                 SL_WISUN_MSG_SEND_ON_SOCKET_CNF_ID,                 sizeof(sl_wisun_msg_send_on_socket_cnf_t) },
        [SL_WISUN_MSG_RECEIVE_ON_SOCKET_REQ_ID]              = { NULL,              sizeof(sl_wisun_msg_receive_on_socket_req_t),              SL_WISUN_MSG_RECEIVE_ON_SOCKET_CNF_ID,              sizeof(sl_wisun_msg_receive_on_socket_cnf_t) },
        [SL_WISUN_MSG_DISCONNECT_REQ_ID]                     = { NULL,              sizeof(sl_wisun_msg_disconnect_req_t),                     SL_WISUN_MSG_DISCONNECT_CNF_ID,                     sizeof(sl_wisun_msg_disconnect_cnf_t) },
        [SL_WISUN_MSG_SET_TRUSTED_CERTIFICATE_REQ_ID]        = { ncp_set_ca,        sizeof(sl_wisun_msg_set_trusted_certificate_req_t),        SL_WISUN_MSG_SET_TRUSTED_CERTIFICATE_CNF_ID,        sizeof(sl_wisun_msg_set_trusted_certificate_cnf_t) },
        [SL_WISUN_MSG_SET_DEVICE_CERTIFICATE_REQ_ID]         = { ncp_set_cert,      sizeof(sl_wisun_msg_set_device_certificate_req_t),         SL_WISUN_MSG_SET_DEVICE_CERTIFICATE_CNF_ID,         sizeof(sl_wisun_msg_set_device_certificate_cnf_t) },
        [SL_WISUN_MSG_SET_DEVICE_PRIVATE_KEY_REQ_ID]         = { ncp_set_key,       sizeof(sl_wisun_msg_set_device_private_key_req_t),         SL_WISUN_MSG_SET_DEVICE_PRIVATE_KEY_CNF_ID,         sizeof(sl_wisun_msg_set_device_private_key_cnf_t) },
        [SL_WISUN_MSG_GET_STATISTICS_REQ_ID]                 = { NULL,              sizeof(sl_wisun_msg_get_statistics_req_t),                 SL_WISUN_MSG_GET_STATISTICS_CNF_ID,                 sizeof(sl_wisun_msg_get_statistics_cnf_t) },
        [SL_WISUN_MSG_SET_SOCKET_OPTION_REQ_ID]              = { ncp_sk_setopt,     sizeof(sl_wisun_msg_set_socket_option_req_t),              SL_WISUN_MSG_SET_SOCKET_OPTION_CNF_ID,              sizeof(sl_wisun_msg_set_socket_option_cnf_t) },
        [SL_WISUN_MSG_SET_TX_POWER_REQ_ID]                   = { ncp_set_txpow,     sizeof(sl_wisun_msg_set_tx_power_req_t),                   SL_WISUN_MSG_SET_TX_POWER_CNF_ID,                   sizeof(sl_wisun_msg_set_tx_power_cnf_t) },
        [SL_WISUN_MSG_SET_CHANNEL_MASK_REQ_ID]               = { NULL,              sizeof(sl_wisun_msg_set_channel_mask_req_t),               SL_WISUN_MSG_SET_CHANNEL_MASK_CNF_ID,               sizeof(sl_wisun_msg_set_channel_mask_cnf_t) },
        [SL_WISUN_MSG_ALLOW_MAC_ADDRESS_REQ_ID]              = { NULL,              sizeof(sl_wisun_msg_allow_mac_address_req_t),              SL_WISUN_MSG_ALLOW_MAC_ADDRESS_CNF_ID,              sizeof(sl_wisun_msg_allow_mac_address_cnf_t) },
        [SL_WISUN_MSG_DENY_MAC_ADDRESS_REQ_ID]               = { NULL,              sizeof(sl_wisun_msg_deny_mac_address_req_t),               SL_WISUN_MSG_DENY_MAC_ADDRESS_CNF_ID,               sizeof(sl_wisun_msg_deny_mac_address_cnf_t) },
        [SL_WISUN_MSG_GET_SOCKET_OPTION_REQ_ID]              = { NULL,              sizeof(sl_wisun_msg_get_socket_option_req_t),              SL_WISUN_MSG_GET_SOCKET_OPTION_CNF_ID,              sizeof(sl_wisun_msg_get_socket_option_cnf_t) },
        [SL_WISUN_MSG_GET_JOIN_STATE_REQ_ID]                 = { ncp_get_join_state, sizeof(sl_wisun_msg_get_join_state_req_t),                SL_WISUN_MSG_GET_JOIN_STATE_CNF_ID,                 sizeof(sl_wisun_msg_get_join_state_cnf_t) },
        [SL_WISUN_MSG_CLEAR_CREDENTIAL_CACHE_REQ_ID]         = { NULL,              sizeof(sl_wisun_msg_clear_credential_cache_req_t),         SL_WISUN_MSG_CLEAR_CREDENTIAL_CACHE_CNF_ID,         sizeof(sl_wisun_msg_clear_credential_cache_cnf_t) },
        [SL_WISUN_MSG_GET_MAC_ADDRESS_REQ_ID]                = { NULL,              sizeof(sl_wisun_msg_get_mac_address_req_t),                SL_WISUN_MSG_GET_MAC_ADDRESS_CNF_ID,                sizeof(sl_wisun_msg_get_mac_address_cnf_t) },
        [SL_WISUN_MSG_SET_MAC_ADDRESS_REQ_ID]                = { NULL,              sizeof(sl_wisun_msg_set_mac_address_req_t),                SL_WISUN_MSG_SET_MAC_ADDRESS_CNF_ID,                sizeof(sl_wisun_msg_set_mac_address_cnf_t) },
        [SL_WISUN_MSG_RESET_STATISTICS_REQ_ID]               = { NULL,              sizeof(sl_wisun_msg_reset_statistics_req_t),               SL_WISUN_MSG_RESET_STATISTICS_CNF_ID,               sizeof(sl_wisun_msg_reset_statistics_cnf_t) },
        [SL_WISUN_MSG_GET_NEIGHBOR_COUNT_REQ_ID]             = { NULL,              sizeof(sl_wisun_msg_get_neighbor_count_req_t),             SL_WISUN_MSG_GET_NEIGHBOR_COUNT_CNF_ID,             sizeof(sl_wisun_msg_get_neighbor_count_cnf_t) },
        [SL_WISUN_MSG_GET_NEIGHBORS_REQ_ID]                  = { NULL,              sizeof(sl_wisun_msg_get_neighbors_req_t),                  SL_WISUN_MSG_GET_NEIGHBORS_CNF_ID,                  sizeof(sl_wisun_msg_get_neighbors_cnf_t) },
        [SL_WISUN_MSG_GET_NEIGHBOR_INFO_REQ_ID]              = { NULL,              sizeof(sl_wisun_msg_get_neighbor_info_req_t),              SL_WISUN_MSG_GET_NEIGHBOR_INFO_CNF_ID,              sizeof(sl_wisun_msg_get_neighbor_info_cnf_t) },
        [SL_WISUN_MSG_SET_UNICAST_SETTINGS_REQ_ID]           = { NULL,              sizeof(sl_wisun_msg_set_unicast_settings_req_t),           SL_WISUN_MSG_SET_UNICAST_SETTINGS_CNF_ID,           sizeof(sl_wisun_msg_set_unicast_settings_cnf_t) },
        [SL_WISUN_MSG_SET_TRACE_LEVEL_REQ_ID]                = { NULL,              sizeof(sl_wisun_msg_set_trace_level_req_t),                SL_WISUN_MSG_SET_TRACE_LEVEL_CNF_ID,                sizeof(sl_wisun_msg_set_trace_level_cnf_t) },
        [SL_WISUN_MSG_SET_TRACE_FILTER_REQ_ID]               = { NULL,              sizeof(sl_wisun_msg_set_trace_filter_req_t),               SL_WISUN_MSG_SET_TRACE_FILTER_CNF_ID,               sizeof(sl_wisun_msg_set_trace_filter_cnf_t) },
        [SL_WISUN_MSG_SET_REGULATION_REQ_ID]                 = { ncp_set_regulation, sizeof(sl_wisun_msg_set_regulation_req_t),                SL_WISUN_MSG_SET_REGULATION_CNF_ID,                 sizeof(sl_wisun_msg_set_regulation_cnf_t) },
        [SL_WISUN_MSG_SET_DEVICE_PRIVATE_KEY_ID_REQ_ID]      = { NULL,              sizeof(sl_wisun_msg_set_device_private_key_id_req_t),      SL_WISUN_MSG_SET_DEVICE_PRIVATE_KEY_ID_CNF_ID,      sizeof(sl_wisun_msg_set_device_private_key_id_cnf_t) },
        [SL_WISUN_MSG_SET_ASYNC_FRAGMENTATION_REQ_ID]        = { NULL,              sizeof(sl_wisun_msg_set_async_fragmentation_req_t),        SL_WISUN_MSG_SET_ASYNC_FRAGMENTATION_CNF_ID,        sizeof(sl_wisun_msg_set_async_fragmentation_cnf_t) },
        [SL_WISUN_MSG_SET_MODE_SWITCH_REQ_ID]                = { NULL,              sizeof(sl_wisun_msg_set_mode_switch_req_t),                SL_WISUN_MSG_SET_MODE_SWITCH_CNF_ID,                sizeof(sl_wisun_msg_set_mode_switch_cnf_t) },
        [SL_WISUN_MSG_SET_REGULATION_TX_THRESHOLDS_REQ_ID]   = { NULL,              sizeof(sl_wisun_msg_set_regulation_tx_thresholds_req_t),   SL_WISUN_MSG_SET_REGULATION_TX_THRESHOLDS_CNF_ID,   sizeof(sl_wisun_msg_set_regulation_tx_thresholds_cnf_t) },
        [SL_WISUN_MSG_SET_DEVICE_TYPE_REQ_ID]                = { ncp_set_devtype,   sizeof(sl_wisun_msg_set_device_type_req_t),                SL_WISUN_MSG_SET_DEVICE_TYPE_CNF_ID,                sizeof(sl_wisun_msg_set_device_type_cnf_t) },
        [SL_WISUN_MSG_SET_CONNECTION_PARAMS_REQ_ID]          = { ncp_set_conparams, sizeof(sl_wisun_msg_set_connection_params_req_t),          SL_WISUN_MSG_SET_CONNECTION_PARAMS_CNF_ID,          sizeof(sl_wisun_msg_set_connection_params_cnf_t) },
        [SL_WISUN_MSG_JOIN_REQ_ID]                           = { ncp_join,          sizeof(sl_wisun_msg_join_req_t) - sizeof(sl_wisun_phy_config_t), SL_WISUN_MSG_JOIN_CNF_ID,                     sizeof(sl_wisun_msg_join_cnf_t) },
        [SL_WISUN_MSG_SET_POM_IE_REQ_ID]                     = { NULL,              sizeof(sl_wisun_msg_set_pom_ie_req_t),                     SL_WISUN_MSG_SET_POM_IE_CNF_ID,                     sizeof(sl_wisun_msg_set_pom_ie_cnf_t) },
        [SL_WISUN_MSG_GET_POM_IE_REQ_ID]                     = { NULL,              sizeof(sl_wisun_msg_get_pom_ie_req_t),                     SL_WISUN_MSG_GET_POM_IE_CNF_ID,                     sizeof(sl_wisun_msg_get_pom_ie_cnf_t) },
        [SL_WISUN_MSG_SET_LFN_PARAMS_REQ_ID]                 = { NULL,              sizeof(sl_wisun_msg_set_lfn_params_req_t),                 SL_WISUN_MSG_SET_LFN_PARAMS_CNF_ID,                 sizeof(sl_wisun_msg_set_lfn_params_cnf_t) },
        [SL_WISUN_MSG_SET_LFN_SUPPORT_REQ_ID]                = { ncp_set_lfn_support, sizeof(sl_wisun_msg_set_lfn_support_req_t),              SL_WISUN_MSG_SET_LFN_SUPPORT_CNF_ID,                sizeof(sl_wisun_msg_set_lfn_support_cnf_t) },
        [SL_WISUN_MSG_SET_PTI_STATE_REQ_ID]                  = { NULL,              sizeof(sl_wisun_msg_set_pti_state_req_t),                  SL_WISUN_MSG_SET_PTI_STATE_CNF_ID,                  sizeof(sl_wisun_msg_set_pti_state_cnf_t) },
        [SL_WISUN_MSG_SET_TBU_SETTINGS_REQ_ID]               = { NULL,              sizeof(sl_wisun_msg_set_tbu_settings_req_t),               SL_WISUN_MSG_SET_TBU_SETTINGS_CNF_ID,               sizeof(sl_wisun_msg_set_tbu_settings_cnf_t) },
        [SL_WISUN_MSG_GET_GTKS_REQ_ID]                       = { NULL,              sizeof(sl_wisun_msg_get_gtks_req_t),                       SL_WISUN_MSG_GET_GTKS_CNF_ID,                       sizeof(sl_wisun_msg_get_gtks_cnf_t) },
        [SL_WISUN_MSG_TRIGGER_FRAME_REQ_ID]                  = { NULL,              sizeof(sl_wisun_msg_trigger_frame_req_t),                  SL_WISUN_MSG_TRIGGER_FRAME_CNF_ID,                  sizeof(sl_wisun_msg_trigger_frame_cnf_t) },
        [SL_WISUN_MSG_GET_STACK_VERSION_REQ_ID]              = { ncp_get_version,   sizeof(sl_wisun_msg_get_stack_version_req_t),              SL_WISUN_MSG_GET_STACK_VERSION_CNF_ID,              sizeof(sl_wisun_msg_get_stack_version_cnf_t) },
        [SL_WISUN_MSG_SET_SECURITY_STATE_REQ_ID]             = { NULL,              sizeof(sl_wisun_msg_set_security_state_req_t),             SL_WISUN_MSG_SET_SECURITY_STATE_CNF_ID,             sizeof(sl_wisun_msg_set_security_state_cnf_t) },
        [SL_WISUN_MSG_GET_NETWORK_INFO_REQ_ID]               = { NULL,              sizeof(sl_wisun_msg_get_network_info_req_t),               SL_WISUN_MSG_GET_NETWORK_INFO_CNF_ID,               sizeof(sl_wisun_msg_get_network_info_cnf_t) },
        [SL_WISUN_MSG_GET_RPL_INFO_REQ_ID]                   = { NULL,              sizeof(sl_wisun_msg_get_rpl_info_req_t),                   SL_WISUN_MSG_GET_RPL_INFO_CNF_ID,                   sizeof(sl_wisun_msg_get_rpl_info_cnf_t) },
        [SL_WISUN_MSG_GET_EXCLUDED_CHANNEL_MASK_REQ_ID]      = { NULL,              sizeof(sl_wisun_msg_get_excluded_channel_mask_req_t),      SL_WISUN_MSG_GET_EXCLUDED_CHANNEL_MASK_CNF_ID,      sizeof(sl_wisun_msg_get_excluded_channel_mask_cnf_t) },
        [SL_WISUN_MSG_SET_NEIGHBOR_TABLE_SIZE_REQ_ID]        = { NULL,              sizeof(sl_wisun_msg_set_neighbor_table_size_req_t),        SL_WISUN_MSG_SET_NEIGHBOR_TABLE_SIZE_CNF_ID,        sizeof(sl_wisun_msg_set_neighbor_table_size_cnf_t) },
        [SL_WISUN_MSG_SOCKET_RECVMSG_REQ_ID]                 = { NULL,              sizeof(sl_wisun_msg_socket_recvmsg_req_t),                 SL_WISUN_MSG_SOCKET_RECVMSG_CNF_ID,                 sizeof(sl_wisun_msg_socket_recvmsg_cnf_t) },
        [SL_WISUN_MSG_SOCKET_SENDMSG_REQ_ID]                 = { NULL,              sizeof(sl_wisun_msg_socket_sendmsg_req_t),                 SL_WISUN_MSG_SOCKET_SENDMSG_CNF_ID,                 sizeof(sl_wisun_msg_socket_sendmsg_cnf_t) },
        [SL_WISUN_MSG_SOCKET_GETSOCKNAME_REQ_ID]             = { NULL,              sizeof(sl_wisun_msg_socket_getsockname_req_t),             SL_WISUN_MSG_SOCKET_GETSOCKNAME_CNF_ID,             sizeof(sl_wisun_msg_socket_getsockname_cnf_t) },
        [SL_WISUN_MSG_SOCKET_GETPEERNAME_REQ_ID]             = { NULL,              sizeof(sl_wisun_msg_socket_getpeername_req_t),             SL_WISUN_MSG_SOCKET_GETPEERNAME_CNF_ID,             sizeof(sl_wisun_msg_socket_getpeername_cnf_t) },
        [SL_WISUN_MSG_ENABLE_NEIGHBOUR_SOLICITATIONS_REQ_ID] = { NULL,              sizeof(sl_wisun_msg_enable_neighbour_solicitations_req_t), SL_WISUN_MSG_ENABLE_NEIGHBOUR_SOLICITATIONS_CNF_ID, sizeof(sl_wisun_msg_enable_neighbour_solicitations_cnf_t) },
        [SL_WISUN_MSG_TRIGGER_NEIGHBOR_CACHE_REFRESH_REQ_ID] = { NULL,              sizeof(sl_wisun_msg_trigger_neighbor_cache_refresh_req_t), SL_WISUN_MSG_TRIGGER_NEIGHBOR_CACHE_REFRESH_CNF_ID, sizeof(sl_wisun_msg_trigger_neighbor_cache_refresh_cnf_t) },
        [SL_WISUN_MSG_SET_RATE_ALGORITHM_REQ_ID]             = { NULL,              sizeof(sl_wisun_msg_set_rate_algorithm_req_t),             SL_WISUN_MSG_SET_RATE_ALGORITHM_CNF_ID,             sizeof(sl_wisun_msg_set_rate_algorithm_cnf_t) },
        [SL_WISUN_MSG_GET_RATE_ALGORITHM_STATS_REQ_ID]       = { NULL,              sizeof(sl_wisun_msg_get_rate_algorithm_stats_req_t),       SL_WISUN_MSG_GET_RATE_ALGORITHM_STATS_CNF_ID,       sizeof(sl_wisun_msg_get_rate_algorithm_stats_cnf_t) },
        [SL_WISUN_MSG_SET_TX_POWER_DDBM_REQ_ID]              = { ncp_set_txpow_ddbm, sizeof(sl_wisun_msg_set_tx_power_ddbm_req_t),             SL_WISUN_MSG_SET_TX_POWER_DDBM_CNF_ID,              sizeof(sl_wisun_msg_set_tx_power_ddbm_cnf_t) },
        [SL_WISUN_MSG_SET_LEAF_REQ_ID]                       = { NULL,              sizeof(sl_wisun_msg_set_leaf_req_t),                       SL_WISUN_MSG_SET_LEAF_CNF_ID,                       sizeof(sl_wisun_msg_set_leaf_cnf_t) },
        [SL_WISUN_MSG_SET_DIRECT_CONNECT_STATE_REQ_ID]       = { NULL,              sizeof(sl_wisun_msg_set_direct_connect_state_req_t),       SL_WISUN_MSG_SET_DIRECT_CONNECT_STATE_CNF_ID,       sizeof(sl_wisun_msg_set_direct_connect_state_cnf_t) },
        [SL_WISUN_MSG_ACCEPT_DIRECT_CONNECT_LINK_REQ_ID]     = { NULL,              sizeof(sl_wisun_msg_accept_direct_connect_link_req_t),     SL_WISUN_MSG_ACCEPT_DIRECT_CONNECT_LINK_CNF_ID,     sizeof(sl_wisun_msg_accept_direct_connect_link_cnf_t) },
        [SL_WISUN_MSG_SET_PHY_SENSITIVITY_REQ_ID]            = { NULL,              sizeof(sl_wisun_msg_set_phy_sensitivity_req_t),            SL_WISUN_MSG_SET_PHY_SENSITIVITY_CNF_ID,            sizeof(sl_wisun_msg_set_phy_sensitivity_cnf_t) },
        [SL_WISUN_MSG_SET_DIRECT_CONNECT_PMK_ID_REQ_ID]      = { NULL,              sizeof(sl_wisun_msg_set_direct_connect_pmk_id_req_t),      SL_WISUN_MSG_SET_DIRECT_CONNECT_PMK_ID_CNF_ID,      sizeof(sl_wisun_msg_set_direct_connect_pmk_id_cnf_t) },
        [SL_WISUN_MSG_SET_PREFERRED_PAN_REQ_ID]              = { NULL,              sizeof(sl_wisun_msg_set_preferred_pan_req_t),              SL_WISUN_MSG_SET_PREFERRED_PAN_CNF_ID,              sizeof(sl_wisun_msg_set_preferred_pan_cnf_t) },
        [SL_WISUN_MSG_CONFIG_NEIGHBOR_TABLE_SIZE_REQ_ID]     = { NULL,              sizeof(sl_wisun_msg_config_neighbor_table_size_req_t),     SL_WISUN_MSG_CONFIG_NEIGHBOR_TABLE_SIZE_CNF_ID,     sizeof(sl_wisun_msg_config_neighbor_table_size_cnf_t) },
        [SL_WISUN_MSG_SET_LFN_TIMINGS_REQ_ID]                = { NULL,              sizeof(sl_wisun_msg_set_lfn_timings_req_t),                SL_WISUN_MSG_SET_LFN_TIMINGS_CNF_ID,                sizeof(sl_wisun_msg_set_lfn_timings_cnf_t) },
        [SL_WISUN_MSG_CONFIG_CONCURRENT_DETECTION_REQ_ID]    = { NULL,              sizeof(sl_wisun_msg_config_concurrent_detection_req_t),    SL_WISUN_MSG_CONFIG_CONCURRENT_DETECTION_CNF_ID,    sizeof(sl_wisun_msg_config_concurrent_detection_cnf_t) },
    };
    const sl_wisun_msg_header_t *req = _req;
    sl_wisun_msg_generic_cnf_t *cnf = _cnf;

    if (req->id >= ARRAY_SIZE(table) || !table[req->id].func)
        FATAL(3, "unsupported NCP message id=0x%02x", req->id);
    if (le16toh(req->length) < table[req->id].req_len)
        FATAL(3, "malformed NCP message id=0x%02x len=%u", req->id, le16toh(req->length));

    // Fill confirmation with a default value
    cnf->header.id     = table[req->id].cnf_id;
    cnf->header.info   = 0;
    cnf->header.length = htole16(table[req->id].cnf_len);
    cnf->body.status   = htole32(SL_STATUS_OK);

    table[req->id].func(req, req_data, cnf, cnf_data);
}

static void ncp_ind_primary_parent_changed(void)
{
    sl_wisun_evt_t ind = { };

    ind.header.id = SL_WISUN_MSG_NETWORK_UPDATE_IND_ID;
    ind.header.length = htole16(sizeof(ind.header) + sizeof(ind.evt.network_update));
    ind.evt.network_update.flags = htole32(1 << SL_WISUN_NETWORK_UPDATE_FLAGS_PRIMARY_PARENT);
    ind.evt.network_update.status = htole32(SL_STATUS_OK);
    ncp_send(&ind);
}

void __real_dbus_emit_change(const char *property_name);
void __wrap_dbus_emit_change(const char *property_name)
{
    if (!strcmp(property_name, "PrimaryParent"))
        ncp_ind_primary_parent_changed();
}

void __real_join_state_transition(struct wsrd *wsrd, enum wsrd_event event);
void __wrap_join_state_transition(struct wsrd *wsrd, enum wsrd_event event)
{
    sl_wisun_evt_t ind = { };
    enum wsrd_state prev;

    prev = wsrd->state;
    __real_join_state_transition(wsrd, event);

    if (prev != wsrd->state) {
        ind.header.id = SL_WISUN_MSG_JOIN_STATE_IND_ID;
        ind.header.length = htole16(sizeof(ind.header) + sizeof(ind.evt.join_state));
        ind.evt.join_state.join_state = htole32(ncp_join_state());
        ind.evt.join_state.status = htole32(SL_STATUS_OK);
        ncp_send(&ind);
    }

    if (prev != WSRD_STATE_OPERATIONAL && wsrd->state == WSRD_STATE_OPERATIONAL) {
        ind.header.id = SL_WISUN_MSG_CONNECTED_IND_ID;
        ind.header.length = htole16(sizeof(ind.header) + sizeof(ind.evt.connected));
        ind.evt.connected.status = htole32(SL_STATUS_OK);
        ncp_send(&ind);
    } else if (prev == WSRD_STATE_OPERATIONAL && wsrd->state != WSRD_STATE_OPERATIONAL) {
        ind.header.id = SL_WISUN_MSG_DISCONNECTED_IND_ID;
        ind.header.length = htole16(sizeof(ind.header) + sizeof(ind.evt.disconnected));
        ind.evt.disconnected.status = htole32(SL_STATUS_OK);
        ncp_send(&ind);
    }
}
