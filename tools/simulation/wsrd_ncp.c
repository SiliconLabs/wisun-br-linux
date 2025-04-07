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
#include <endian.h>

#include "common/log.h"

void ns3_ncp_recv(const void *_req, const void *req_data, void *_cnf, void *cnf_data)
{
    static const struct {
        void (*func)(const void *, const void *, void *, void *);
        uint16_t req_len;
        uint8_t  cnf_id;
        uint16_t cnf_len;
    } table[] = {
        [SL_WISUN_MSG_SET_NETWORK_SIZE_REQ_ID]               = { NULL,              sizeof(sl_wisun_msg_set_network_size_req_t),               SL_WISUN_MSG_SET_NETWORK_SIZE_CNF_ID,               sizeof(sl_wisun_msg_set_network_size_cnf_t) },
        [SL_WISUN_MSG_GET_IP_ADDRESS_REQ_ID]                 = { NULL,              sizeof(sl_wisun_msg_get_ip_address_req_t),                 SL_WISUN_MSG_GET_IP_ADDRESS_CNF_ID,                 sizeof(sl_wisun_msg_get_ip_address_cnf_t) },
        [SL_WISUN_MSG_OPEN_SOCKET_REQ_ID]                    = { NULL,              sizeof(sl_wisun_msg_open_socket_req_t),                    SL_WISUN_MSG_OPEN_SOCKET_CNF_ID,                    sizeof(sl_wisun_msg_open_socket_cnf_t) },
        [SL_WISUN_MSG_CLOSE_SOCKET_REQ_ID]                   = { NULL,              sizeof(sl_wisun_msg_close_socket_req_t),                   SL_WISUN_MSG_CLOSE_SOCKET_CNF_ID,                   sizeof(sl_wisun_msg_close_socket_cnf_t) },
        [SL_WISUN_MSG_SENDTO_ON_SOCKET_REQ_ID]               = { NULL,              sizeof(sl_wisun_msg_sendto_on_socket_req_t),               SL_WISUN_MSG_SENDTO_ON_SOCKET_CNF_ID,               sizeof(sl_wisun_msg_sendto_on_socket_cnf_t) },
        [SL_WISUN_MSG_LISTEN_ON_SOCKET_REQ_ID]               = { NULL,              sizeof(sl_wisun_msg_listen_on_socket_req_t),               SL_WISUN_MSG_LISTEN_ON_SOCKET_CNF_ID,               sizeof(sl_wisun_msg_listen_on_socket_cnf_t) },
        [SL_WISUN_MSG_ACCEPT_ON_SOCKET_REQ_ID]               = { NULL,              sizeof(sl_wisun_msg_accept_on_socket_req_t),               SL_WISUN_MSG_ACCEPT_ON_SOCKET_CNF_ID,               sizeof(sl_wisun_msg_accept_on_socket_cnf_t) },
        [SL_WISUN_MSG_CONNECT_SOCKET_REQ_ID]                 = { NULL,              sizeof(sl_wisun_msg_connect_socket_req_t),                 SL_WISUN_MSG_CONNECT_SOCKET_CNF_ID,                 sizeof(sl_wisun_msg_connect_socket_cnf_t) },
        [SL_WISUN_MSG_BIND_SOCKET_REQ_ID]                    = { NULL,              sizeof(sl_wisun_msg_bind_socket_req_t),                    SL_WISUN_MSG_BIND_SOCKET_CNF_ID,                    sizeof(sl_wisun_msg_bind_socket_cnf_t) },
        [SL_WISUN_MSG_SEND_ON_SOCKET_REQ_ID]                 = { NULL,              sizeof(sl_wisun_msg_send_on_socket_req_t),                 SL_WISUN_MSG_SEND_ON_SOCKET_CNF_ID,                 sizeof(sl_wisun_msg_send_on_socket_cnf_t) },
        [SL_WISUN_MSG_RECEIVE_ON_SOCKET_REQ_ID]              = { NULL,              sizeof(sl_wisun_msg_receive_on_socket_req_t),              SL_WISUN_MSG_RECEIVE_ON_SOCKET_CNF_ID,              sizeof(sl_wisun_msg_receive_on_socket_cnf_t) },
        [SL_WISUN_MSG_DISCONNECT_REQ_ID]                     = { NULL,              sizeof(sl_wisun_msg_disconnect_req_t),                     SL_WISUN_MSG_DISCONNECT_CNF_ID,                     sizeof(sl_wisun_msg_disconnect_cnf_t) },
        [SL_WISUN_MSG_SET_TRUSTED_CERTIFICATE_REQ_ID]        = { NULL,              sizeof(sl_wisun_msg_set_trusted_certificate_req_t),        SL_WISUN_MSG_SET_TRUSTED_CERTIFICATE_CNF_ID,        sizeof(sl_wisun_msg_set_trusted_certificate_cnf_t) },
        [SL_WISUN_MSG_SET_DEVICE_CERTIFICATE_REQ_ID]         = { NULL,              sizeof(sl_wisun_msg_set_device_certificate_req_t),         SL_WISUN_MSG_SET_DEVICE_CERTIFICATE_CNF_ID,         sizeof(sl_wisun_msg_set_device_certificate_cnf_t) },
        [SL_WISUN_MSG_SET_DEVICE_PRIVATE_KEY_REQ_ID]         = { NULL,              sizeof(sl_wisun_msg_set_device_private_key_req_t),         SL_WISUN_MSG_SET_DEVICE_PRIVATE_KEY_CNF_ID,         sizeof(sl_wisun_msg_set_device_private_key_cnf_t) },
        [SL_WISUN_MSG_GET_STATISTICS_REQ_ID]                 = { NULL,              sizeof(sl_wisun_msg_get_statistics_req_t),                 SL_WISUN_MSG_GET_STATISTICS_CNF_ID,                 sizeof(sl_wisun_msg_get_statistics_cnf_t) },
        [SL_WISUN_MSG_SET_SOCKET_OPTION_REQ_ID]              = { NULL,              sizeof(sl_wisun_msg_set_socket_option_req_t),              SL_WISUN_MSG_SET_SOCKET_OPTION_CNF_ID,              sizeof(sl_wisun_msg_set_socket_option_cnf_t) },
        [SL_WISUN_MSG_SET_TX_POWER_REQ_ID]                   = { NULL,              sizeof(sl_wisun_msg_set_tx_power_req_t),                   SL_WISUN_MSG_SET_TX_POWER_CNF_ID,                   sizeof(sl_wisun_msg_set_tx_power_cnf_t) },
        [SL_WISUN_MSG_SET_CHANNEL_MASK_REQ_ID]               = { NULL,              sizeof(sl_wisun_msg_set_channel_mask_req_t),               SL_WISUN_MSG_SET_CHANNEL_MASK_CNF_ID,               sizeof(sl_wisun_msg_set_channel_mask_cnf_t) },
        [SL_WISUN_MSG_ALLOW_MAC_ADDRESS_REQ_ID]              = { NULL,              sizeof(sl_wisun_msg_allow_mac_address_req_t),              SL_WISUN_MSG_ALLOW_MAC_ADDRESS_CNF_ID,              sizeof(sl_wisun_msg_allow_mac_address_cnf_t) },
        [SL_WISUN_MSG_DENY_MAC_ADDRESS_REQ_ID]               = { NULL,              sizeof(sl_wisun_msg_deny_mac_address_req_t),               SL_WISUN_MSG_DENY_MAC_ADDRESS_CNF_ID,               sizeof(sl_wisun_msg_deny_mac_address_cnf_t) },
        [SL_WISUN_MSG_GET_SOCKET_OPTION_REQ_ID]              = { NULL,              sizeof(sl_wisun_msg_get_socket_option_req_t),              SL_WISUN_MSG_GET_SOCKET_OPTION_CNF_ID,              sizeof(sl_wisun_msg_get_socket_option_cnf_t) },
        [SL_WISUN_MSG_GET_JOIN_STATE_REQ_ID]                 = { NULL,              sizeof(sl_wisun_msg_get_join_state_req_t),                 SL_WISUN_MSG_GET_JOIN_STATE_CNF_ID,                 sizeof(sl_wisun_msg_get_join_state_cnf_t) },
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
        [SL_WISUN_MSG_SET_REGULATION_REQ_ID]                 = { NULL,              sizeof(sl_wisun_msg_set_regulation_req_t),                 SL_WISUN_MSG_SET_REGULATION_CNF_ID,                 sizeof(sl_wisun_msg_set_regulation_cnf_t) },
        [SL_WISUN_MSG_SET_DEVICE_PRIVATE_KEY_ID_REQ_ID]      = { NULL,              sizeof(sl_wisun_msg_set_device_private_key_id_req_t),      SL_WISUN_MSG_SET_DEVICE_PRIVATE_KEY_ID_CNF_ID,      sizeof(sl_wisun_msg_set_device_private_key_id_cnf_t) },
        [SL_WISUN_MSG_SET_ASYNC_FRAGMENTATION_REQ_ID]        = { NULL,              sizeof(sl_wisun_msg_set_async_fragmentation_req_t),        SL_WISUN_MSG_SET_ASYNC_FRAGMENTATION_CNF_ID,        sizeof(sl_wisun_msg_set_async_fragmentation_cnf_t) },
        [SL_WISUN_MSG_SET_MODE_SWITCH_REQ_ID]                = { NULL,              sizeof(sl_wisun_msg_set_mode_switch_req_t),                SL_WISUN_MSG_SET_MODE_SWITCH_CNF_ID,                sizeof(sl_wisun_msg_set_mode_switch_cnf_t) },
        [SL_WISUN_MSG_SET_REGULATION_TX_THRESHOLDS_REQ_ID]   = { NULL,              sizeof(sl_wisun_msg_set_regulation_tx_thresholds_req_t),   SL_WISUN_MSG_SET_REGULATION_TX_THRESHOLDS_CNF_ID,   sizeof(sl_wisun_msg_set_regulation_tx_thresholds_cnf_t) },
        [SL_WISUN_MSG_SET_DEVICE_TYPE_REQ_ID]                = { NULL,              sizeof(sl_wisun_msg_set_device_type_req_t),                SL_WISUN_MSG_SET_DEVICE_TYPE_CNF_ID,                sizeof(sl_wisun_msg_set_device_type_cnf_t) },
        [SL_WISUN_MSG_SET_CONNECTION_PARAMS_REQ_ID]          = { NULL,              sizeof(sl_wisun_msg_set_connection_params_req_t),          SL_WISUN_MSG_SET_CONNECTION_PARAMS_CNF_ID,          sizeof(sl_wisun_msg_set_connection_params_cnf_t) },
        [SL_WISUN_MSG_JOIN_REQ_ID]                           = { NULL,              sizeof(sl_wisun_msg_join_req_t),                           SL_WISUN_MSG_JOIN_CNF_ID,                           sizeof(sl_wisun_msg_join_cnf_t) },
        [SL_WISUN_MSG_SET_POM_IE_REQ_ID]                     = { NULL,              sizeof(sl_wisun_msg_set_pom_ie_req_t),                     SL_WISUN_MSG_SET_POM_IE_CNF_ID,                     sizeof(sl_wisun_msg_set_pom_ie_cnf_t) },
        [SL_WISUN_MSG_GET_POM_IE_REQ_ID]                     = { NULL,              sizeof(sl_wisun_msg_get_pom_ie_req_t),                     SL_WISUN_MSG_GET_POM_IE_CNF_ID,                     sizeof(sl_wisun_msg_get_pom_ie_cnf_t) },
        [SL_WISUN_MSG_SET_LFN_PARAMS_REQ_ID]                 = { NULL,              sizeof(sl_wisun_msg_set_lfn_params_req_t),                 SL_WISUN_MSG_SET_LFN_PARAMS_CNF_ID,                 sizeof(sl_wisun_msg_set_lfn_params_cnf_t) },
        [SL_WISUN_MSG_SET_LFN_SUPPORT_REQ_ID]                = { NULL,              sizeof(sl_wisun_msg_set_lfn_support_req_t),                SL_WISUN_MSG_SET_LFN_SUPPORT_CNF_ID,                sizeof(sl_wisun_msg_set_lfn_support_cnf_t) },
        [SL_WISUN_MSG_SET_PTI_STATE_REQ_ID]                  = { NULL,              sizeof(sl_wisun_msg_set_pti_state_req_t),                  SL_WISUN_MSG_SET_PTI_STATE_CNF_ID,                  sizeof(sl_wisun_msg_set_pti_state_cnf_t) },
        [SL_WISUN_MSG_SET_TBU_SETTINGS_REQ_ID]               = { NULL,              sizeof(sl_wisun_msg_set_tbu_settings_req_t),               SL_WISUN_MSG_SET_TBU_SETTINGS_CNF_ID,               sizeof(sl_wisun_msg_set_tbu_settings_cnf_t) },
        [SL_WISUN_MSG_GET_GTKS_REQ_ID]                       = { NULL,              sizeof(sl_wisun_msg_get_gtks_req_t),                       SL_WISUN_MSG_GET_GTKS_CNF_ID,                       sizeof(sl_wisun_msg_get_gtks_cnf_t) },
        [SL_WISUN_MSG_TRIGGER_FRAME_REQ_ID]                  = { NULL,              sizeof(sl_wisun_msg_trigger_frame_req_t),                  SL_WISUN_MSG_TRIGGER_FRAME_CNF_ID,                  sizeof(sl_wisun_msg_trigger_frame_cnf_t) },
        [SL_WISUN_MSG_GET_STACK_VERSION_REQ_ID]              = { NULL,              sizeof(sl_wisun_msg_get_stack_version_req_t),              SL_WISUN_MSG_GET_STACK_VERSION_CNF_ID,              sizeof(sl_wisun_msg_get_stack_version_cnf_t) },
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
        [SL_WISUN_MSG_SET_TX_POWER_DDBM_REQ_ID]              = { NULL,              sizeof(sl_wisun_msg_set_tx_power_ddbm_req_t),              SL_WISUN_MSG_SET_TX_POWER_DDBM_CNF_ID,              sizeof(sl_wisun_msg_set_tx_power_ddbm_cnf_t) },
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
