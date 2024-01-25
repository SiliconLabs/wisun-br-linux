/*
 * Copyright (c) 2018-2021, Pelion and affiliates.
 * Copyright (c) 2021-2023 Silicon Laboratories Inc. (www.silabs.com)
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#define _GNU_SOURCE
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <fnmatch.h>
#include "app_wsbrd/wsbr.h"
#include "common/rand.h"
#include "common/bits.h"
#include "common/key_value_storage.h"
#include "common/log_legacy.h"
#include "common/endian.h"
#include "common/events_scheduler.h"
#include "common/sys_queue_extra.h"
#include "common/specs/ip.h"

#include "core/timers.h"
#include "nwk_interface/protocol.h"
#include "core/ns_buffer.h"
#include "core/ns_address_internal.h"
#include "6lowpan/bootstraps/protocol_6lowpan.h"
#include "6lowpan/lowpan_adaptation_interface.h"
#include "rpl/rpl.h"

#include "6lowpan/mac/mpx_api.h"
#include "6lowpan/ws/ws_bbr_api.h"
#include "6lowpan/ws/ws_llc.h"
#include "6lowpan/ws/ws_config.h"
#include "6lowpan/ws/ws_common.h"
#include "6lowpan/ws/ws_bootstrap.h"
#include "6lowpan/ws/ws_cfg_settings.h"
#include "6lowpan/ws/ws_pae_key_storage.h"
#include "6lowpan/ws/ws_pae_controller.h"
#include "6lowpan/ws/ws_bootstrap_6lbr.h"
#include "6lowpan/ws/ws_management_api.h"

#include "6lowpan/ws/ws_bbr_api.h"

#define TRACE_GROUP "BBRw"

#define RPL_INSTANCE_ID 1

#define WS_ULA_LIFETIME 24*3600
#define WS_ROUTE_LIFETIME WS_ULA_LIFETIME
#define BBR_CHECK_INTERVAL 60
#define BBR_BACKUP_ULA_DELAY 300

/* when creating BBR make ULA dodag ID always and when network becomes available add prefix to DHCP
 *
 *
 */
static uint32_t pan_version_timer = 0;

static uint16_t ws_bbr_fhss_bsi = 0;
static uint16_t ws_bbr_pan_id = 0xffff;

static int8_t ws_bbr_nvm_info_read(uint16_t *bsi, uint16_t *pan_id)
{
    struct storage_parse_info *info = storage_open_prefix("br-info", "r");
    int ret;

    if (!info)
        return -1;
    for (;;) {
        ret = storage_parse_line(info);
        if (ret == EOF)
            break;
        if (ret) {
            WARN("%s:%d: invalid line: '%s'", info->filename, info->linenr, info->line);
        } else if (!fnmatch("bsi", info->key, 0)) {
            *bsi = strtoul(info->value, NULL, 0);
        } else if (!fnmatch("pan_id", info->key, 0)) {
            *pan_id = strtoul(info->value, NULL, 0);
        } else {
            WARN("%s:%d: invalid key: '%s'", info->filename, info->linenr, info->line);
        }
    }
    storage_close(info);
    return 0;
}

static void ws_bbr_nvm_info_write(uint16_t bsi, uint16_t pan_id)
{
    struct storage_parse_info *info = storage_open_prefix("br-info", "w");

    if (!info)
        return;
    fprintf(info->file, "# Broadcast Schedule Identifier\n");
    fprintf(info->file, "bsi = %d\n", bsi);
    fprintf(info->file, "pan_id = %#04x\n", pan_id);
    storage_close(info);
}

bool ws_bbr_backbone_address_get(struct net_if *cur, uint8_t *address)
{
    const uint8_t *addr;

    addr = addr_select_with_prefix(cur, NULL, 0, SOCKET_IPV6_PREFER_SRC_PUBLIC | SOCKET_IPV6_PREFER_SRC_6LOWPAN_SHORT);
    if (!addr)
        return false;
    memcpy(address, addr, 16);
    return true;
}

void ws_bbr_pan_version_increase(struct net_if *cur)
{
    if (!cur) {
        return;
    }
    tr_debug("Border router version number update");
    // Version number is not periodically increased forcing nodes to check Border router availability using DAO
    pan_version_timer = 0;
    cur->ws_info.pan_information.pan_version++;
    // Inconsistent for border router to make information distribute faster
    ws_bootstrap_configuration_trickle_reset(cur);

    // Indicate new pan version to PAE controller
    ws_pae_controller_pan_version_set(cur, cur->ws_info.pan_information.pan_version);
}

void ws_bbr_lfn_version_increase(struct net_if *cur)
{
    if (!cur) {
        return;
    }
    tr_debug("Border router LFN version number update");
    cur->ws_info.pan_information.lfn_version++;
    // Inconsistent for border router to make information distribute faster
    ws_bootstrap_configuration_trickle_reset(cur);

    // Indicate new lfn version to PAE controller
    ws_pae_controller_lfn_version_set(cur, cur->ws_info.pan_information.lfn_version);
    //   Wi-SUN FAN 1.1v06 6.3.4.6.3 FFN Discovery / Join
    // A Border Router MUST increment PAN Version (PANVER-IE) [...] when [...]
    // the following occurs:
    // d. A change in LFN Version.
    ws_bbr_pan_version_increase(cur);
}

uint16_t test_pan_size_override = 0xffff;

uint16_t ws_bbr_pan_size(struct net_if *cur)
{
    if (!cur) {
        return 0;
    }

    if (test_pan_size_override != 0xffff) {
        return test_pan_size_override;
    }

    return SLIST_SIZE(&g_ctxt.rpl_root.targets, link);
}

static void ws_bbr_forwarding_cb(struct net_if *interface, buffer_t *buf)
{
    uint8_t traffic_class = buf->options.traffic_class >> IP_TCLASS_DSCP_SHIFT;

    if (traffic_class == IP_DSCP_EF) {
        //indicate EF forwarding to adaptation
        lowpan_adaptation_expedite_forward_enable(interface);
    }
}

void ws_bbr_init(struct net_if *interface)
{
    (void) interface;
    //Read From NVM
    if (ws_bbr_nvm_info_read(&ws_bbr_fhss_bsi, &ws_bbr_pan_id) < 0) {
        //NVM value not available Randomize Value Here by first time
        ws_bbr_fhss_bsi = rand_get_16bit();
        tr_debug("Randomized init value BSI %u", ws_bbr_fhss_bsi);
    } else {
        tr_debug("Read BSI %u from NVM", ws_bbr_fhss_bsi);
        tr_debug("Read PAN ID %u from NVM", ws_bbr_pan_id);
    }
    interface->if_common_forwarding_out_cb = &ws_bbr_forwarding_cb;
}

uint16_t ws_bbr_bsi_generate(void)
{
    ws_bbr_nvm_info_write(ws_bbr_fhss_bsi, ws_bbr_pan_id);
    return ws_bbr_fhss_bsi;
}

uint16_t ws_bbr_pan_id_get(struct net_if *interface)
{
    (void) interface;
    return ws_bbr_pan_id;
}

int ws_bbr_routing_table_get(int8_t interface_id, bbr_route_info_t *table_ptr, uint16_t table_len)
{
    struct rpl_root *root = &g_ctxt.rpl_root;
    struct rpl_transit *transit;
    struct rpl_target *target;
    int cnt = 0;

    SLIST_FOREACH(target, &root->targets, link) {
        transit = rpl_transit_preferred(root, target);
        if (!transit)
            continue;
        memcpy(table_ptr[cnt].target, target->prefix + 8, 8);
        memcpy(table_ptr[cnt].parent, transit->parent + 8, 8);
        cnt++;
        if (cnt >= table_len)
            break;
    }
    return cnt;
}

int ws_bbr_pan_configuration_set(int8_t interface_id, uint16_t pan_id)
{
    if (ws_bbr_pan_id != pan_id) {
        ws_bbr_pan_id = pan_id;
        // Store to NVM and restart bootstrap
        ws_bbr_nvm_info_write(ws_bbr_fhss_bsi, ws_bbr_pan_id);
    }
    return 0;
}

int ws_bbr_radius_address_set(int8_t interface_id, const struct sockaddr_storage *address)
{
    return ws_pae_controller_radius_address_set(interface_id, address);
}

int ws_bbr_radius_shared_secret_set(int8_t interface_id, const uint16_t shared_secret_len, const uint8_t *shared_secret)
{
    return ws_pae_controller_radius_shared_secret_set(interface_id, shared_secret_len, shared_secret);
}

int ws_bbr_set_mode_switch(int8_t interface_id, int mode, uint8_t phy_mode_id, uint8_t *neighbor_mac_address)
{
    struct net_if *interface = protocol_stack_interface_info_get_by_id(interface_id);
    if (interface == NULL)
        return -1;

    uint8_t all_nodes[8] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}; //only for wsbrd-v1.5-rc1

    if (neighbor_mac_address)
        return ws_llc_set_mode_switch(interface, mode, phy_mode_id, neighbor_mac_address);
    return ws_llc_set_mode_switch(interface, mode, phy_mode_id, all_nodes);

}
