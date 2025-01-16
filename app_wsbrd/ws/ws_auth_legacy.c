/*
 * SPDX-License-Identifier: LicenseRef-MSLA
 * Copyright (c) 2021-2025 Silicon Laboratories Inc. (www.silabs.com)
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
#include <errno.h>
#include <string.h>

#include "app_wsbrd/app/commandline.h"
#include "app_wsbrd/app/wsbr_cfg.h"
#include "app_wsbrd/net/protocol.h"
#include "app_wsbrd/security/eapol/eapol_helper.h"
#include "app_wsbrd/security/kmp/kmp_socket_if.h"
#include "app_wsbrd/ws/ws_bootstrap.h"
#include "app_wsbrd/ws/ws_eapol_pdu.h"
#include "app_wsbrd/ws/ws_eapol_auth_relay.h"
#include "app_wsbrd/ws/ws_eapol_relay.h"
#include "app_wsbrd/ws/ws_llc.h"
#include "app_wsbrd/ws/ws_pae_controller.h"
#include "common/specs/ieee802159.h"
#include "common/log_legacy.h"
#include "common/memutils.h"

#include "ws_auth.h"

#define TRACE_GROUP "auth"

#define EAPOL_RELAY_SOCKET_PORT               10253
#define BR_EAPOL_RELAY_SOCKET_PORT            10255
#define PAE_AUTH_SOCKET_PORT                  10254

static bool ws_auth_congestion_get(struct net_if *net_if)
{
    uint16_t adaptation_average = 0;
    uint16_t llc_eapol_average = 0;
    uint16_t llc_average = 0;
    uint16_t average_sum = 0;
    bool ret;

    if (!net_if)
        return false;

    // Read the values for adaptation and LLC queues
    adaptation_average = red_aq_get(&net_if->random_early_detection);
    llc_eapol_average  = red_aq_get(&net_if->llc_eapol_random_early_detection);
    llc_average        = red_aq_get(&net_if->llc_random_early_detection);
    // Calculate combined average
    average_sum = adaptation_average + llc_average + llc_eapol_average;
    // Check drop probability
    average_sum = red_aq_calc(&net_if->pae_random_early_detection, average_sum);
    ret = red_congestion_check(&net_if->pae_random_early_detection);

    tr_info("Congestion check, summed averageQ: %i adapt averageQ: %i LLC averageQ: %i LLC EAPOL averageQ: %i drop: %s",
            average_sum, adaptation_average, llc_average, llc_eapol_average, ret ? "T" : "F");

    return ret;
}

static int8_t ws_auth_ip_addr_get(struct net_if *interface_ptr, uint8_t *address)
{
    const uint8_t *addr;

    addr = addr_select_with_prefix(interface_ptr, NULL, 0, SOCKET_IPV6_PREFER_SRC_PUBLIC | SOCKET_IPV6_PREFER_SRC_6LOWPAN_SHORT);
    if (!addr)
        return -1;

    memcpy(address, addr, 16);
    return 0;
}

void ws_auth_init(struct net_if *net_if, const struct wsbrd_conf *conf)
{
    struct mpx_api *mpx_api = ws_llc_mpx_api_get(net_if);
    struct sec_timing timing_ffn = {
        .pmk_lifetime_s          = conf->auth_cfg.ffn.pmk_lifetime_s,
        .ptk_lifetime_s          = conf->auth_cfg.ffn.ptk_lifetime_s,
        .expire_offset           = conf->auth_cfg.ffn.gtk_expire_offset_s,
        .new_act_time            = conf->auth_cfg.ffn.gtk_new_activation_time,
        .new_install_req         = conf->auth_cfg.ffn.gtk_new_install_required,
        .revocat_lifetime_reduct = conf->ws_ffn_revocation_lifetime_reduction,
    };
    struct sec_timing timing_lfn = {
        .pmk_lifetime_s          = conf->auth_cfg.lfn.pmk_lifetime_s,
        .ptk_lifetime_s          = conf->auth_cfg.lfn.ptk_lifetime_s,
        .expire_offset           = conf->auth_cfg.lfn.gtk_expire_offset_s,
        .new_act_time            = conf->auth_cfg.lfn.gtk_new_activation_time,
        .new_install_req         = conf->auth_cfg.lfn.gtk_new_install_required,
        .revocat_lifetime_reduct = conf->ws_lfn_revocation_lifetime_reduction,
    };
    struct arm_certificate_entry tls_br = {
        .cert     = conf->auth_cfg.cert.iov_base,
        .cert_len = conf->auth_cfg.cert.iov_len,
        .key      = conf->auth_cfg.key.iov_base,
        .key_len  = conf->auth_cfg.key.iov_len,
    };
    struct arm_certificate_entry tls_ca = {
        .cert     = conf->auth_cfg.ca_cert.iov_base,
        .cert_len = conf->auth_cfg.ca_cert.iov_len,
    };
    const uint8_t *lgtks[3] = { };
    const uint8_t *gtks[4] = { };
    uint8_t addr_linklocal[16];
    bool force = false;

    ws_pae_controller_init(net_if);
    ws_pae_controller_cb_register(net_if,
                                  ws_bootstrap_nw_key_set,
                                  ws_bootstrap_nw_key_index_set,
                                  ws_mngt_pan_version_increase,
                                  ws_mngt_lfn_version_increase,
                                  ws_auth_congestion_get);

    ws_eapol_pdu_init(net_if);
    ws_eapol_pdu_mpx_register(net_if, mpx_api, MPX_ID_KMP);

    ws_pae_controller_configure(net_if, &timing_ffn, &timing_lfn,
                                &size_params[conf->ws_size].security_protocol_config);

    if (conf->auth_cfg.radius_secret[0])
        ws_pae_controller_radius_shared_secret_set(net_if->id, strlen(conf->auth_cfg.radius_secret),
                                                   (uint8_t *)conf->auth_cfg.radius_secret);
    if (conf->auth_cfg.radius_addr.ss_family != AF_UNSPEC)
        ws_pae_controller_radius_address_set(net_if->id, &conf->auth_cfg.radius_addr);

    force = false;
    for (int i = 0; i < ARRAY_SIZE(conf->ws_gtk_force); i++) {
        if (conf->ws_gtk_force[i]) {
            force = true;
            gtks[i] = conf->ws_gtk[i];
        }
    }
    if (force)
        ws_pae_controller_gtk_update(net_if->id, gtks);

    force = false;
    for (int i = 0; i < ARRAY_SIZE(conf->ws_lgtk_force); i++) {
        if (conf->ws_lgtk_force[i]) {
            force = true;
            lgtks[i] = conf->ws_lgtk[i];
        }
    }
    if (force)
        ws_pae_controller_lgtk_update(net_if->id, lgtks);

    ws_pae_controller_own_certificate_add(&tls_br);
    ws_pae_controller_trusted_certificate_add(&tls_ca);

    // Clear Pending Key Index State
    net_if->ws_info.ffn_gtk_index = 0;
    net_if->ws_info.lfn_gtk_index = 0;

    ws_pae_controller_auth_init(net_if);
    addr_interface_get_ll_address(net_if, addr_linklocal, 1);
    // Set EAPOL relay to port 10255 and authenticator relay to 10253 (and to own ll address)
    ws_eapol_relay_start(net_if, BR_EAPOL_RELAY_SOCKET_PORT, addr_linklocal, EAPOL_RELAY_SOCKET_PORT);
    // Set authenticator relay to port 10253 and PAE to 10254 (and to own ll address)
    ws_eapol_auth_relay_start(net_if, EAPOL_RELAY_SOCKET_PORT, addr_linklocal, PAE_AUTH_SOCKET_PORT);
    // Send network name to controller
    ws_pae_controller_network_name_set(net_if, net_if->ws_info.network_name);
    // Set backbone IP address get callback
    ws_pae_controller_auth_cb_register(net_if, ws_auth_ip_addr_get);
    // Set PAE port to 10254 and authenticator relay to 10253 (and to own ll address)
    ws_pae_controller_authenticator_start(net_if, PAE_AUTH_SOCKET_PORT, addr_linklocal, EAPOL_RELAY_SOCKET_PORT);
}

int ws_auth_fd_eapol_relay(struct net_if *net_if)
{
    return ws_eapol_auth_relay_get_socket_fd();
}

void ws_auth_recv_eapol_relay(struct net_if *net_if)
{
    ws_eapol_auth_relay_socket_cb(ws_auth_fd_eapol_relay(net_if));
}

int ws_auth_fd_radius(struct net_if *net_if)
{
    return kmp_socket_if_get_radius_sockfd();
}

void ws_auth_recv_radius(struct net_if *net_if)
{
    kmp_socket_if_radius_socket_cb(ws_auth_fd_radius(net_if));
}

const uint8_t *ws_auth_gtk(struct net_if *net_if, int key_index)
{
    const bool is_lgtk = key_index > WS_GTK_COUNT;
    const int offset = is_lgtk ? WS_GTK_COUNT : 0;
    sec_prot_gtk_keys_t *keys;

    keys = ws_pae_controller_get_transient_keys(net_if->id, is_lgtk);
    return keys->gtk[key_index - offset - 1].key;
}

void ws_auth_gtkhash(struct net_if *net_if, uint8_t gtkhash[WS_GTK_COUNT][8])
{
    memcpy(gtkhash, ws_pae_controller_gtk_hash_ptr_get(net_if), WS_GTK_COUNT * 8);
}

void ws_auth_lgtkhash(struct net_if *net_if, uint8_t lgtkhash[WS_LGTK_COUNT][8])
{
    memcpy(lgtkhash, ws_pae_controller_lgtk_hash_ptr_get(net_if), WS_LGTK_COUNT * 8);
}

uint8_t ws_auth_lgtk_index(struct net_if *net_if)
{
    return ws_pae_controller_lgtk_active_index_get(net_if);
}

bool ws_auth_is_1st_msg(struct net_if *net_if, const void *buf, size_t buf_len)
{
    const uint8_t *buf_ptr = buf;
    eapol_pdu_t eapol_pdu;
    uint8_t kmp_type = *buf_ptr++;
    buf_len--;
    if (!eapol_parse_pdu_header(buf_ptr, buf_len, &eapol_pdu)) {
        return false;
    }
    if (eapol_pdu.packet_type == EAPOL_EAP_TYPE) {
        if (eapol_pdu.msg.eap.eap_code == EAP_REQ && eapol_pdu.msg.eap.type == EAP_IDENTITY) {
            return true;
        }
    } else {

        uint8_t key_mask = eapol_pdu_key_mask_get(&eapol_pdu);
        if (kmp_type == 6 && key_mask == KEY_INFO_KEY_ACK) {
            //FWK first message validation
            return true;
        } else if (kmp_type == 7 && key_mask == (KEY_INFO_KEY_ACK | KEY_INFO_KEY_MIC | KEY_INFO_SECURED_KEY_FRAME)) {
            //GWK first message validation
            return true;
        }
    }

    return false;
}

int ws_auth_revoke_pmk(struct net_if *net_if, const struct eui64 *eui64)
{
    int ret;

    ret = ws_pae_controller_node_keys_remove(net_if->id, eui64->u8);
    return ret < 0 ? -EINVAL : 0;
}
