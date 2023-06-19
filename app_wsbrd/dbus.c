/*
 * Copyright (c) 2021-2023 Silicon Laboratories Inc. (www.silabs.com)
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
#include <limits.h>
#include <arpa/inet.h>
#include <systemd/sd-bus.h>
#include "app_wsbrd/tun.h"
#include "common/named_values.h"
#include "common/utils.h"
#include "common/log.h"
#include "stack/ws_bbr_api.h"

#include "stack/source/6lowpan/ws/ws_common.h"
#include "stack/source/6lowpan/ws/ws_pae_controller.h"
#include "stack/source/6lowpan/ws/ws_pae_key_storage.h"
#include "stack/source/6lowpan/ws/ws_pae_lib.h"
#include "stack/source/6lowpan/ws/ws_pae_auth.h"
#include "stack/source/6lowpan/ws/ws_cfg_settings.h"
#include "stack/source/6lowpan/ws/ws_bootstrap.h"
#include "stack/source/6lowpan/ws/ws_llc.h"
#include "stack/source/nwk_interface/protocol.h"
#include "stack/source/security/protocols/sec_prot_keys.h"
#include "stack/source/common_protocols/icmpv6.h"

#include "commandline_values.h"
#include "rcp_api.h"
#include "wsbr.h"
#include "tun.h"

#include "dbus.h"

static int dbus_set_slot_algorithm(sd_bus_message *m, void *userdata, sd_bus_error *ret_error)
{
    int ret;
    uint8_t mode;

    ret = sd_bus_message_read(m, "y", &mode);
    if (ret < 0)
        return sd_bus_error_set_errno(ret_error, -ret);

    if (mode == 0)
        rcp_set_tx_allowance_level(WS_TX_AND_RX_SLOT, WS_TX_AND_RX_SLOT);
    else if (mode == 1)
        rcp_set_tx_allowance_level(WS_TX_SLOT, WS_TX_SLOT);
    else
        return sd_bus_error_set_errno(ret_error, EINVAL);
    sd_bus_reply_method_return(m, NULL);

    return 0;
}

int dbus_set_mode_switch(sd_bus_message *m, void *userdata, sd_bus_error *ret_error)
{
    struct wsbr_ctxt *ctxt = userdata;
    int ret;
    uint8_t *eui64;
    size_t eui64_len;
    int phy_mode_id;

    ret = sd_bus_message_read_array(m, 'y', (const void **)&eui64, &eui64_len);
    if (ret < 0)
        return sd_bus_error_set_errno(ret_error, -ret);

    ret = sd_bus_message_read_basic(m, 'i', &phy_mode_id);
    if (ret < 0)
        return sd_bus_error_set_errno(ret_error, -ret);

    if (eui64_len == 0)
        eui64 = NULL;
    else if (eui64_len != 8)
        return sd_bus_error_set_errno(ret_error, EINVAL);

    if (phy_mode_id > 0)
        ret = ws_bbr_set_mode_switch(ctxt->rcp_if_id, 1, phy_mode_id, eui64); // mode switch enabled
    else if (phy_mode_id == -1)
        ret = ws_bbr_set_mode_switch(ctxt->rcp_if_id, -1, 0, eui64); // mode switch disabled
    else if (phy_mode_id == 0)
        ret = ws_bbr_set_mode_switch(ctxt->rcp_if_id, 0, 0, eui64); // mode switch back to default

    if (ret < 0)
        return sd_bus_error_set_errno(ret_error, EINVAL);
    sd_bus_reply_method_return(m, NULL);

    return 0;
}

int dbus_join_multicast_group(sd_bus_message *m, void *userdata, sd_bus_error *ret_error)
{
    struct wsbr_ctxt *ctxt = userdata;
    struct net_if *cur = protocol_stack_interface_info_get_by_id(ctxt->rcp_if_id);
    const uint8_t *ipv6;
    size_t len;
    int ret;

    if (!cur)
        return sd_bus_error_set_errno(ret_error, EFAULT);

    ret = sd_bus_message_read_array(m, 'y', (const void **)&ipv6, &len);
    if (ret < 0)
        return sd_bus_error_set_errno(ret_error, -ret);
    if (len != 16)
        return sd_bus_error_set_errno(ret_error, EINVAL);

    ret = wsbr_tun_join_mcast_group(ctxt->sock_mcast, ctxt->config.tun_dev, ipv6);
    if (ret < 0)
        return sd_bus_error_set_errno(ret_error, errno);
    addr_add_group(cur, ipv6);
    sd_bus_reply_method_return(m, NULL);
    return 0;
}

int dbus_leave_multicast_group(sd_bus_message *m, void *userdata, sd_bus_error *ret_error)
{
    struct wsbr_ctxt *ctxt = userdata;
    struct net_if *cur = protocol_stack_interface_info_get_by_id(ctxt->rcp_if_id);
    const uint8_t *ipv6;
    size_t len;
    int ret;

    if (!cur)
        return sd_bus_error_set_errno(ret_error, EFAULT);

    ret = sd_bus_message_read_array(m, 'y', (const void **)&ipv6, &len);
    if (ret < 0)
        return sd_bus_error_set_errno(ret_error, -ret);
    if (len != 16)
        return sd_bus_error_set_errno(ret_error, EINVAL);

    wsbr_tun_leave_mcast_group(ctxt->sock_mcast, ctxt->config.tun_dev, ipv6);
    if (ret < 0)
        return sd_bus_error_set_errno(ret_error, errno);
    addr_remove_group(cur, ipv6);
    sd_bus_reply_method_return(m, NULL);
    return 0;
}

void dbus_emit_keys_change(struct wsbr_ctxt *ctxt)
{
    sd_bus_emit_properties_changed(ctxt->dbus,
                       "/com/silabs/Wisun/BorderRouter",
                       "com.silabs.Wisun.BorderRouter",
                       "Gtks", NULL);
    sd_bus_emit_properties_changed(ctxt->dbus,
                       "/com/silabs/Wisun/BorderRouter",
                       "com.silabs.Wisun.BorderRouter",
                       "Gaks", NULL);
    sd_bus_emit_properties_changed(ctxt->dbus,
                       "/com/silabs/Wisun/BorderRouter",
                       "com.silabs.Wisun.BorderRouter",
                       "Lgtks", NULL);
    sd_bus_emit_properties_changed(ctxt->dbus,
                       "/com/silabs/Wisun/BorderRouter",
                       "com.silabs.Wisun.BorderRouter",
                       "Lgaks", NULL);
}

static int dbus_get_transient_keys(sd_bus_message *reply, void *userdata,
                                   sd_bus_error *ret_error, bool is_lfn)
{
    int interface_id = *(int *)userdata;
    sec_prot_gtk_keys_t *gtks = ws_pae_controller_get_transient_keys(interface_id, is_lfn);
    const int key_cnt = is_lfn ? LGTK_NUM : GTK_NUM;
    int ret;

    if (!gtks)
        return sd_bus_error_set_errno(ret_error, EBADR);
    ret = sd_bus_message_open_container(reply, 'a', "ay");
    WARN_ON(ret < 0, "%s", strerror(-ret));
    for (int i = 0; i < key_cnt; i++) {
        ret = sd_bus_message_append_array(reply, 'y', gtks->gtk[i].key, ARRAY_SIZE(gtks->gtk[i].key));
        WARN_ON(ret < 0, "%s", strerror(-ret));
    }
    ret = sd_bus_message_close_container(reply);
    WARN_ON(ret < 0, "%s", strerror(-ret));
    return 0;
}

static int dbus_get_gtks(sd_bus *bus, const char *path, const char *interface,
                         const char *property, sd_bus_message *reply,
                         void *userdata, sd_bus_error *ret_error)
{
    return dbus_get_transient_keys(reply, userdata, ret_error, false);
}

static int dbus_get_lgtks(sd_bus *bus, const char *path, const char *interface,
                          const char *property, sd_bus_message *reply,
                          void *userdata, sd_bus_error *ret_error)
{
    return dbus_get_transient_keys(reply, userdata, ret_error, true);
}

static int dbus_get_aes_keys(sd_bus_message *reply, void *userdata,
                             sd_bus_error *ret_error, bool is_lfn)
{
    int interface_id = *(int *)userdata;
    struct net_if *interface_ptr = protocol_stack_interface_info_get_by_id(interface_id);
    sec_prot_gtk_keys_t *gtks = ws_pae_controller_get_transient_keys(interface_id, is_lfn);
    const int key_cnt = is_lfn ? LGTK_NUM : GTK_NUM;
    uint8_t gak[16];
    int ret;

    if (!gtks || !interface_ptr || !interface_ptr->ws_info.cfg)
        return sd_bus_error_set_errno(ret_error, EBADR);
    ret = sd_bus_message_open_container(reply, 'a', "ay");
    WARN_ON(ret < 0, "%s", strerror(-ret));
    for (int i = 0; i < key_cnt; i++) {
        // GAK is SHA256 of network name concatened with GTK
        ws_pae_controller_gak_from_gtk(gak, gtks->gtk[i].key, interface_ptr->ws_info.cfg->gen.network_name);
        ret = sd_bus_message_append_array(reply, 'y', gak, ARRAY_SIZE(gak));
        WARN_ON(ret < 0, "%s", strerror(-ret));
    }
    ret = sd_bus_message_close_container(reply);
    WARN_ON(ret < 0, "%s", strerror(-ret));
    return 0;
}

static int dbus_get_gaks(sd_bus *bus, const char *path, const char *interface,
                         const char *property, sd_bus_message *reply,
                         void *userdata, sd_bus_error *ret_error)
{
    return dbus_get_aes_keys(reply, userdata, ret_error, false);
}

static int dbus_get_lgaks(sd_bus *bus, const char *path, const char *interface,
                          const char *property, sd_bus_message *reply,
                          void *userdata, sd_bus_error *ret_error)
{
    return dbus_get_aes_keys(reply, userdata, ret_error, true);
}

static int dbus_revoke_pairwise_keys(sd_bus_message *m, void *userdata, sd_bus_error *ret_error)
{
    struct wsbr_ctxt *ctxt = userdata;
    size_t eui64_len;
    uint8_t *eui64;
    int ret;

    ret = sd_bus_message_read_array(m, 'y', (const void **)&eui64, &eui64_len);
    if (ret < 0)
        return sd_bus_error_set_errno(ret_error, -ret);
    if (eui64_len != 8)
        return sd_bus_error_set_errno(ret_error, EINVAL);
    ret = ws_bbr_node_keys_remove(ctxt->rcp_if_id, eui64);
    if (ret < 0)
        return sd_bus_error_set_errno(ret_error, EINVAL);
    sd_bus_reply_method_return(m, NULL);
    return 0;
}

static int dbus_revoke_group_keys(sd_bus_message *m, void *userdata, sd_bus_error *ret_error)
{
    struct wsbr_ctxt *ctxt = userdata;
    uint8_t *gtk, *lgtk;
    size_t len;
    int ret;

    ret = sd_bus_message_read_array(m, 'y', (const void **)&gtk, &len);
    if (ret < 0)
        return sd_bus_error_set_errno(ret_error, -ret);
    if (!len)
        gtk = NULL;
    else if (len != GTK_LEN)
        return sd_bus_error_set_errno(ret_error, EINVAL);
    ret = sd_bus_message_read_array(m, 'y', (const void **)&lgtk, &len);
    if (ret < 0)
        return sd_bus_error_set_errno(ret_error, -ret);
    if (!len)
        lgtk = NULL;
    else if (len != GTK_LEN)
        return sd_bus_error_set_errno(ret_error, EINVAL);

    ret = ws_bbr_node_access_revoke_start(ctxt->rcp_if_id, false, gtk);
    if (ret < 0)
        return sd_bus_error_set_errno(ret_error, EINVAL);
    ret = ws_bbr_node_access_revoke_start(ctxt->rcp_if_id, true, lgtk);
    if (ret < 0)
        return sd_bus_error_set_errno(ret_error, EINVAL);

    sd_bus_reply_method_return(m, NULL);
    return 0;
}

static int dbus_install_group_key(sd_bus_message *m, void *userdata,
                                  sd_bus_error *ret_error, bool is_lgtk)
{
    struct wsbr_ctxt *ctxt = userdata;
    const uint8_t *gtk;
    size_t len;
    int ret;

    ret = sd_bus_message_read_array(m, 'y', (const void **)&gtk, &len);
    if (ret < 0)
        return sd_bus_error_set_errno(ret_error, -ret);
    if (len != GTK_LEN)
        return sd_bus_error_set_errno(ret_error, EINVAL);

    ws_pae_auth_gtk_install(ctxt->rcp_if_id, gtk, is_lgtk);

    sd_bus_reply_method_return(m, NULL);
    return 0;
}

static int dbus_install_gtk(sd_bus_message *m, void *userdata, sd_bus_error *ret_error)
{
    return dbus_install_group_key(m, userdata, ret_error, false);
}

static int dbus_install_lgtk(sd_bus_message *m, void *userdata, sd_bus_error *ret_error)
{
    return dbus_install_group_key(m, userdata, ret_error, true);
}

void dbus_emit_nodes_change(struct wsbr_ctxt *ctxt)
{
    sd_bus_emit_properties_changed(ctxt->dbus,
                       "/com/silabs/Wisun/BorderRouter",
                       "com.silabs.Wisun.BorderRouter",
                       "Nodes", NULL);
}

static int dbus_message_open_info(sd_bus_message *m, const char *property,
                                  const char *name, const char *type)
{
    int ret;

    ret = sd_bus_message_open_container(m, 'e', "sv");
    WARN_ON(ret < 0, "%s: %s", property, strerror(-ret));
    ret = sd_bus_message_append(m, "s", name);
    WARN_ON(ret < 0, "%s: %s", property, strerror(-ret));
    ret = sd_bus_message_open_container(m, 'v', type);
    WARN_ON(ret < 0, "%s: %s", property, strerror(-ret));
    return ret;
}

static int dbus_message_close_info(sd_bus_message *m, const char *property)
{
    int ret;

    ret = sd_bus_message_close_container(m);
    WARN_ON(ret < 0, "%s: %s", property, strerror(-ret));
    ret = sd_bus_message_close_container(m);
    WARN_ON(ret < 0, "%s: %s", property, strerror(-ret));
    return ret;
}

struct neighbor_info {
    int rssi;
    int rsl;
    int rsl_adv;
};

static int dbus_message_append_node(
    sd_bus_message *m,
    const char *property,
    const uint8_t self[8],
    const uint8_t parent[8],
    const uint8_t ipv6[][16],
    bool is_br,
    supp_entry_t *supp,
    struct neighbor_info *neighbor)
{
    int ret, val;

    ret = sd_bus_message_open_container(m, 'r', "aya{sv}");
    WARN_ON(ret < 0, "%s: %s", property, strerror(-ret));
    ret = sd_bus_message_append_array(m, 'y', self, 8);
    WARN_ON(ret < 0, "%s: %s", property, strerror(-ret));
    ret = sd_bus_message_open_container(m, 'a', "{sv}");
    WARN_ON(ret < 0, "%s: %s", property, strerror(-ret));
    {
        if (is_br) {
            dbus_message_open_info(m, property, "is_border_router", "b");
            ret = sd_bus_message_append(m, "b", true);
            WARN_ON(ret < 0, "%s: %s", property, strerror(-ret));
            dbus_message_close_info(m, property);
            // TODO: deprecate is_border_router
            dbus_message_open_info(m, property, "node_role", "y");
            ret = sd_bus_message_append(m, "y", WS_NR_ROLE_BR);
            WARN_ON(ret < 0, "%s: %s", property, strerror(-ret));
            dbus_message_close_info(m, property);
        } else if (supp) {
            dbus_message_open_info(m, property, "is_authenticated", "b");
            val = true;
            ret = sd_bus_message_append(m, "b", val);
            WARN_ON(ret < 0, "%s: %s", property, strerror(-ret));
            dbus_message_close_info(m, property);
            if (ws_common_is_valid_nr(supp->sec_keys.node_role)) {
                dbus_message_open_info(m, property, "node_role", "y");
                ret = sd_bus_message_append(m, "y", supp->sec_keys.node_role);
                WARN_ON(ret < 0, "%s: %s", property, strerror(-ret));
                dbus_message_close_info(m, property);
            }
        }
        if (parent) {
            dbus_message_open_info(m, property, "parent", "ay");
            ret = sd_bus_message_append_array(m, 'y', parent, 8);
            WARN_ON(ret < 0, "%s: %s", property, strerror(-ret));
            dbus_message_close_info(m, property);
        }
        if (neighbor) {
            dbus_message_open_info(m, property, "is_neighbor", "b");
            ret = sd_bus_message_append(m, "b", true);
            WARN_ON(ret < 0, "%s: %s", property, strerror(-ret));
            dbus_message_close_info(m, property);

            dbus_message_open_info(m, property, "rssi", "i");
            ret = sd_bus_message_append_basic(m, 'i', &neighbor->rssi);
            WARN_ON(ret < 0, "%s: %s", property, strerror(-ret));
            dbus_message_close_info(m, property);
            if (neighbor->rsl != INT_MIN) {
                dbus_message_open_info(m, property, "rsl", "i");
                ret = sd_bus_message_append_basic(m, 'i', &neighbor->rsl);
                WARN_ON(ret < 0, "%s: %s", property, strerror(-ret));
                dbus_message_close_info(m, property);
            }
            if (neighbor->rsl_adv != INT_MIN) {
                dbus_message_open_info(m, property, "rsl_adv", "i");
                ret = sd_bus_message_append_basic(m, 'i', &neighbor->rsl_adv);
                WARN_ON(ret < 0, "%s: %s", property, strerror(-ret));
                dbus_message_close_info(m, property);
            }
        }
        dbus_message_open_info(m, property, "ipv6", "aay");
        ret = sd_bus_message_open_container(m, 'a', "ay");
        WARN_ON(ret < 0, "%s: %s", property, strerror(-ret));
        for (; memcmp(*ipv6, ADDR_UNSPECIFIED, 16); ipv6++) {
            ret = sd_bus_message_append_array(m, 'y', *ipv6, 16);
            WARN_ON(ret < 0, "%s: %s", property, strerror(-ret));
        }
        ret = sd_bus_message_close_container(m);
        WARN_ON(ret < 0, "%s: %s", property, strerror(-ret));
        dbus_message_close_info(m, property);
    }
    ret = sd_bus_message_close_container(m);
    WARN_ON(ret < 0, "%s: %s", property, strerror(-ret));
    ret = sd_bus_message_close_container(m);
    WARN_ON(ret < 0, "%s: %s", property, strerror(-ret));
    return ret;
}

static uint8_t *dhcp_eui64_to_ipv6(struct wsbr_ctxt *ctxt, const uint8_t eui64[8])
{
    for (int i = 0; i < ctxt->dhcp_leases_len; i++)
        if (!memcmp(eui64, ctxt->dhcp_leases[i].eui64, 8))
            return ctxt->dhcp_leases[i].ipv6;
    return NULL;
}

static uint8_t *dhcp_ipv6_to_eui64(struct wsbr_ctxt *ctxt, const uint8_t ipv6[16])
{
    for (int i = 0; i < ctxt->dhcp_leases_len; i++)
        if (!memcmp(ipv6, ctxt->dhcp_leases[i].ipv6, 16))
            return ctxt->dhcp_leases[i].eui64;
    return NULL;
}

static bool dbus_get_neighbor_info(struct wsbr_ctxt *ctxt, struct neighbor_info *info, const uint8_t eui64[8])
{
    struct net_if *net_if = protocol_stack_interface_info_get_by_id(ctxt->rcp_if_id);
    ws_neighbor_class_entry_t *neighbor_ws = NULL;
    ws_neighbor_temp_class_t *neighbor_ws_tmp;
    llc_neighbour_req_t neighbor_llc;

    neighbor_ws_tmp = ws_llc_get_eapol_temp_entry(net_if, eui64);
    if (!neighbor_ws_tmp)
        neighbor_ws_tmp = ws_llc_get_multicast_temp_entry(net_if, eui64);
    if (neighbor_ws_tmp) {
        neighbor_ws = &neighbor_ws_tmp->neigh_info_list;
        neighbor_ws->rssi = neighbor_ws_tmp->signal_dbm;
    }
    if (!neighbor_ws) {
        if (ws_bootstrap_neighbor_get(net_if, eui64, &neighbor_llc))
            neighbor_ws = neighbor_llc.ws_neighbor;
        else
            return false;
    }
    info->rssi = neighbor_ws->rssi;
    info->rsl = neighbor_ws->rsl_in == RSL_UNITITIALIZED
              ? INT_MIN
              : -174 + ws_neighbor_class_rsl_in_get(neighbor_ws);
    info->rsl_adv = neighbor_ws->rsl_in == RSL_UNITITIALIZED
                  ? INT_MIN
                  : -174 + ws_neighbor_class_rsl_out_get(neighbor_ws);
    return true;
}

int dbus_get_nodes(sd_bus *bus, const char *path, const char *interface,
                       const char *property, sd_bus_message *reply,
                       void *userdata, sd_bus_error *ret_error)
{
    struct neighbor_info *neighbor_info_ptr;
    struct neighbor_info neighbor_info;
    struct wsbr_ctxt *ctxt = userdata;
    uint8_t node_ipv6[3][16] = { 0 };
    bbr_route_info_t table[4096];
    uint8_t *parent, *ucast_addr;
    int len_pae, len_rpl, ret, j;
    uint8_t eui64_pae[4096][8];
    bbr_information_t br_info;
    supp_entry_t *supp;
    uint8_t ipv6[16];

    ret = ws_bbr_info_get(ctxt->rcp_if_id, &br_info);
    if (ret)
        return sd_bus_error_set_errno(ret_error, EAGAIN);
    len_pae = ws_pae_auth_supp_list(ctxt->rcp_if_id, eui64_pae, sizeof(eui64_pae));
    len_rpl = ws_bbr_routing_table_get(ctxt->rcp_if_id, table, ARRAY_SIZE(table));
    if (len_rpl < 0)
        return sd_bus_error_set_errno(ret_error, EAGAIN);

    ret = sd_bus_message_open_container(reply, 'a', "(aya{sv})");
    WARN_ON(ret < 0, "%s: %s", property, strerror(-ret));
    tun_addr_get_link_local(ctxt->config.tun_dev, node_ipv6[0]);
    tun_addr_get_global_unicast(ctxt->config.tun_dev, node_ipv6[1]);
    dbus_message_append_node(reply, property, ctxt->rcp.eui64, NULL,
                             node_ipv6, true, false, NULL);

    for (int i = 0; i < len_pae; i++) {
        memcpy(node_ipv6[0], ADDR_LINK_LOCAL_PREFIX, 8);
        memcpy(node_ipv6[0] + 8, eui64_pae[i], 8);
        memcpy(node_ipv6[1], ADDR_UNSPECIFIED, 16);
        parent = NULL;
        ucast_addr = dhcp_eui64_to_ipv6(ctxt, eui64_pae[i]);
        if (ucast_addr) {
            memcpy(node_ipv6[1], ucast_addr, 16);
            for (j = 0; j < len_rpl; j++)
                if (!memcmp(table[j].target, node_ipv6[1] + 8, 8))
                    break;
            if (j != len_rpl) {
                memcpy(ipv6, br_info.prefix, 8);
                memcpy(ipv6 + 8, table[j].parent, 8);
                parent = dhcp_ipv6_to_eui64(ctxt, ipv6);
                WARN_ON(!parent, "RPL parent not in DHCP leases (%s)", tr_ipv6(ipv6));
            }
        }
        if (dbus_get_neighbor_info(ctxt, &neighbor_info, eui64_pae[i]))
            neighbor_info_ptr = &neighbor_info;
        else
            neighbor_info_ptr = NULL;
        if (ws_pae_key_storage_supp_exists(eui64_pae[i]))
            supp = ws_pae_key_storage_supp_read(NULL, eui64_pae[i], NULL, NULL, NULL);
        else
            supp = NULL;
        dbus_message_append_node(reply, property, eui64_pae[i], parent, node_ipv6,
                                 false, supp, neighbor_info_ptr);
        if (supp)
            free(supp);
    }
    ret = sd_bus_message_close_container(reply);
    WARN_ON(ret < 0, "d %s: %s", property, strerror(-ret));
    return 0;
}

int dbus_get_hw_address(sd_bus *bus, const char *path, const char *interface,
                        const char *property, sd_bus_message *reply,
                        void *userdata, sd_bus_error *ret_error)
{
    uint8_t *hw_addr = userdata;
    int ret;

    ret = sd_bus_message_append_array(reply, 'y', hw_addr, 8);
    WARN_ON(ret < 0, "%s", strerror(-ret));
    return 0;
}

int dbus_get_ws_pan_id(sd_bus *bus, const char *path, const char *interface,
                       const char *property, sd_bus_message *reply,
                       void *userdata, sd_bus_error *ret_error)
{
    struct net_if *net_if = protocol_stack_interface_info_get_by_id(*(int *)userdata);
    int ret;

    if (!net_if)
        return sd_bus_error_set_errno(ret_error, EINVAL);
    ret = sd_bus_message_append(reply, "q", net_if->ws_info.network_pan_id);
    WARN_ON(ret < 0, "%s: %s", property, strerror(-ret));
    return 0;
}

int wsbrd_get_ws_domain(sd_bus *bus, const char *path, const char *interface,
                        const char *property, sd_bus_message *reply,
                        void *userdata, sd_bus_error *ret_error)
{
    int *domain = userdata;
    int ret;

    ret = sd_bus_message_append(reply, "s", val_to_str(*domain, valid_ws_domains, "[unknown]"));
    WARN_ON(ret < 0, "%s", strerror(-ret));
    return 0;
}

int wsbrd_get_ws_size(sd_bus *bus, const char *path, const char *interface,
                        const char *property, sd_bus_message *reply,
                        void *userdata, sd_bus_error *ret_error)
{
    int *size = userdata;
    int ret;

    ret = sd_bus_message_append(reply, "s", val_to_str(*size, valid_ws_size, NULL));
    WARN_ON(ret < 0, "%s", strerror(-ret));
    return 0;
}

int dbus_get_string(sd_bus *bus, const char *path, const char *interface,
               const char *property, sd_bus_message *reply,
               void *userdata, sd_bus_error *ret_error)
{
    char *val = userdata;
    int ret;

    ret = sd_bus_message_append(reply, "s", val);
    WARN_ON(ret < 0, "%s: %s", property, strerror(-ret));
    return 0;
}

static const sd_bus_vtable dbus_vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_METHOD("JoinMulticastGroup", "ay", NULL,
                      dbus_join_multicast_group, 0),
        SD_BUS_METHOD("LeaveMulticastGroup", "ay", NULL,
                      dbus_leave_multicast_group, 0),
        SD_BUS_METHOD("SetModeSwitch", "ayi", NULL,
                      dbus_set_mode_switch, 0),
        SD_BUS_METHOD("SetSlotAlgorithm", "y", NULL,
                      dbus_set_slot_algorithm, 0),
        SD_BUS_METHOD("RevokePairwiseKeys", "ay", NULL,
                      dbus_revoke_pairwise_keys, 0),
        SD_BUS_METHOD("RevokeGroupKeys", "ayay", NULL,
                      dbus_revoke_group_keys, 0),
        SD_BUS_METHOD("InstallGtk", "ay", NULL,
                      dbus_install_gtk, 0),
        SD_BUS_METHOD("InstallLgtk", "ay", NULL,
                      dbus_install_lgtk, 0),
        SD_BUS_PROPERTY("Gtks", "aay", dbus_get_gtks,
                        offsetof(struct wsbr_ctxt, rcp_if_id),
                        SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("Gaks", "aay", dbus_get_gaks,
                        offsetof(struct wsbr_ctxt, rcp_if_id),
                        SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("Lgtks", "aay", dbus_get_lgtks,
                        offsetof(struct wsbr_ctxt, rcp_if_id),
                        SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("Lgaks", "aay", dbus_get_lgaks,
                        offsetof(struct wsbr_ctxt, rcp_if_id),
                        SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("Nodes", "a(aya{sv})", dbus_get_nodes, 0,
                        SD_BUS_VTABLE_PROPERTY_EMITS_INVALIDATION),
        SD_BUS_PROPERTY("HwAddress", "ay", dbus_get_hw_address,
                        offsetof(struct wsbr_ctxt, rcp.eui64),
                        0),
        SD_BUS_PROPERTY("WisunNetworkName", "s", dbus_get_string,
                        offsetof(struct wsbr_ctxt, config.ws_name),
                        SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("WisunSize", "s", wsbrd_get_ws_size,
                        offsetof(struct wsbr_ctxt, config.ws_size),
                        SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("WisunDomain", "s", wsbrd_get_ws_domain,
                        offsetof(struct wsbr_ctxt, config.ws_domain),
                        SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("WisunMode", "u", NULL,
                        offsetof(struct wsbr_ctxt, config.ws_mode),
                        SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("WisunClass", "u", NULL,
                        offsetof(struct wsbr_ctxt, config.ws_class),
                        SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("WisunPhyModeId", "u", NULL,
                        offsetof(struct wsbr_ctxt, config.ws_phy_mode_id),
                        SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("WisunChanPlanId", "u", NULL,
                        offsetof(struct wsbr_ctxt, config.ws_chan_plan_id),
                        SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("WisunPanId", "q", dbus_get_ws_pan_id,
                        offsetof(struct wsbr_ctxt, rcp_if_id),
                        SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("WisunFanVersion", "y", NULL,
                        offsetof(struct wsbr_ctxt, config.ws_fan_version),
                        SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_VTABLE_END
};

void dbus_register(struct wsbr_ctxt *ctxt)
{
    int ret;
    char mode = 'A';
    const char *env_var;
    const char *dbus_scope = "undefined";

    env_var = getenv("DBUS_STARTER_BUS_TYPE");
    if (env_var && !strcmp(env_var, "system"))
        mode = 'S';
    if (env_var && !strcmp(env_var, "user"))
        mode = 'U';
    if (env_var && !strcmp(env_var, "session"))
        mode = 'U';
    if (mode == 'U' || mode == 'A')
        ret = sd_bus_default_user(&ctxt->dbus);
    if (mode == 'S' || (mode == 'A' && ret < 0))
        ret = sd_bus_default_system(&ctxt->dbus);
    if (ret < 0) {
        WARN("DBus not available: %s", strerror(-ret));
        return;
    }

    ret = sd_bus_add_object_vtable(ctxt->dbus, NULL, "/com/silabs/Wisun/BorderRouter",
                                   "com.silabs.Wisun.BorderRouter",
                                   dbus_vtable, ctxt);
    if (ret < 0) {
        WARN("%s: %s", __func__, strerror(-ret));
        return;
    }

    ret = sd_bus_request_name(ctxt->dbus, "com.silabs.Wisun.BorderRouter",
                              SD_BUS_NAME_ALLOW_REPLACEMENT | SD_BUS_NAME_REPLACE_EXISTING);
    if (ret < 0) {
        WARN("%s: %s", __func__, strerror(-ret));
        return;
    }

    sd_bus_get_scope(ctxt->dbus, &dbus_scope);
    INFO("Successfully registered to %s DBus", dbus_scope);
}

int dbus_process(struct wsbr_ctxt *ctxt)
{
    BUG_ON(!ctxt->dbus);
    sd_bus_process(ctxt->dbus, NULL);
    return 0;
}

int dbus_get_fd(struct wsbr_ctxt *ctxt)
{
    if (ctxt->dbus)
        return sd_bus_get_fd(ctxt->dbus);
    else
        return -1;
}
