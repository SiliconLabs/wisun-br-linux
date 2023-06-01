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
#include "stack/net_interface.h"
#include "stack/ws_management_api.h"
#include "stack/net_rpl.h"
#include "stack/ws_bbr_api.h"
#include "stack/timers.h"

#include "nwk_interface/protocol.h"
#include "rpl/rpl_control.h"
#include "rpl/rpl_data.h"
#include "common_protocols/icmpv6.h"
#include "common_protocols/ip.h"
#include "6lowpan/bootstraps/protocol_6lowpan.h"
#include "6lowpan/bootstraps/protocol_6lowpan_interface.h"
#include "6lowpan/lowpan_adaptation_interface.h"

#include "6lowpan/mac/mpx_api.h"
#include "6lowpan/ws/ws_llc.h"
#include "6lowpan/ws/ws_config.h"
#include "6lowpan/ws/ws_common.h"
#include "6lowpan/ws/ws_bootstrap.h"
#include "6lowpan/ws/ws_cfg_settings.h"
#include "6lowpan/ws/ws_pae_key_storage.h"
#include "6lowpan/ws/ws_bbr_api_internal.h"
#include "6lowpan/ws/ws_pae_controller.h"
#include "6lowpan/ws/ws_bootstrap_6lbr.h"

#define TRACE_GROUP "BBRw"

#define RPL_INSTANCE_ID 1

static uint8_t current_instance_id = RPL_INSTANCE_ID;

#define WS_ULA_LIFETIME 24*3600
#define WS_ROUTE_LIFETIME WS_ULA_LIFETIME
#define BBR_CHECK_INTERVAL 60
#define BBR_BACKUP_ULA_DELAY 300

/* when creating BBR make ULA dodag ID always and when network becomes available add prefix to DHCP
 *
 *
 */
static int8_t backbone_interface_id = -1; // BBR backbone information
static uint16_t configuration = 0;
static uint32_t pan_version_timer = 0;

static uint8_t static_dodag_prefix[8] = {0xfd, 0x00, 0x72, 0x83, 0x7e};
static uint8_t static_dodag_id_prefix[8] = {0xfd, 0x00, 0x61, 0x72, 0x6d};
static uint8_t current_dodag_id[16] = {0};
static uint8_t current_local_prefix[8] = {0};
static uint8_t current_global_prefix[16] = {0}; // DHCP requires 16 bytes prefix
static uint32_t bbr_delay_timer = 0; // initial delay.
static uint32_t global_prefix_unavailable_timer = 0; // initial delay.

static rpl_dodag_conf_t rpl_conf = {
    // Lifetime values
    .default_lifetime = 120,
    .lifetime_unit = 60,
    .objective_code_point = 1, // MRHOF algorithm used
    .authentication = false,
    .path_control_size = 7,
    .dag_max_rank_increase = WS_RPL_MAX_HOP_RANK_INCREASE,
    .min_hop_rank_increase = WS_RPL_MIN_HOP_RANK_INCREASE,
    // DIO configuration
    .dio_interval_min = WS_RPL_DIO_IMIN_SMALL,
    .dio_interval_doublings = WS_RPL_DIO_DOUBLING_SMALL,
    .dio_redundancy_constant = WS_RPL_DIO_REDUNDANCY_SMALL
};

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

static void ws_bbr_rpl_version_timer_start(struct net_if *cur, uint8_t version)
{
    // Set the next timeout value for version update
    if (version < 128) {
        //stable version for RPL so slow timer update is ok
        cur->ws_info.rpl_version_timer = RPL_VERSION_LIFETIME;
    } else {
        if (ws_cfg_network_config_get(cur) <= CONFIG_SMALL) {
            // Also handles CONFIG_CERTIFICATE
            cur->ws_info.rpl_version_timer = RPL_VERSION_LIFETIME_RESTART_SMALL;
        } else if (ws_cfg_network_config_get(cur) <= CONFIG_MEDIUM) {
            cur->ws_info.rpl_version_timer = RPL_VERSION_LIFETIME_RESTART_MEDIUM;
        } else if (ws_cfg_network_config_get(cur) <= CONFIG_LARGE) {
            cur->ws_info.rpl_version_timer = RPL_VERSION_LIFETIME_RESTART_LARGE;
        } else  {
            cur->ws_info.rpl_version_timer = RPL_VERSION_LIFETIME_RESTART_EXTRA_LARGE;
        }
    }
}

static void ws_bbr_rpl_version_increase(struct net_if *cur)
{
    if (!protocol_6lowpan_rpl_root_dodag) {
        return;
    }
    ws_bbr_rpl_version_timer_start(cur, rpl_control_increment_dodag_version(protocol_6lowpan_rpl_root_dodag));
}

int ws_bbr_get_backbone_id()
{
    return backbone_interface_id;
}

void ws_bbr_rpl_config(struct net_if *cur, uint8_t imin, uint8_t doubling, uint8_t redundancy, uint16_t dag_max_rank_increase, uint16_t min_hop_rank_increase, uint32_t lifetime)
{
    if (imin == 0 || doubling == 0) {
        // use default values
        imin = WS_RPL_DIO_IMIN_SMALL;
        doubling = WS_RPL_DIO_DOUBLING_SMALL;
        redundancy = WS_RPL_DIO_REDUNDANCY_SMALL;
    }
    uint8_t lifetime_unit = 60;
    uint8_t default_lifetime;

    if (lifetime == 0) {
        // 2 hours default lifetime
        lifetime = 120 * 60;
    } else if (lifetime <= 250 * 60) {
        // Lifetime unit of 60 is ok up to 4 hours
    } else if (lifetime <= 250 * 120) {
        //more than 4 hours needs larger lifetime unit
        lifetime_unit = 120;
    } else if (lifetime <= 250 * 240) {
        lifetime_unit = 240;
    } else {
        // Maximum lifetime is 16 hours 40 minutes
        lifetime = 250 * 240;
        lifetime_unit = 240;
    }
    default_lifetime = lifetime / lifetime_unit;

    if (rpl_conf.dio_interval_min == imin &&
            rpl_conf.dio_interval_doublings == doubling &&
            rpl_conf.dio_redundancy_constant == redundancy &&
            rpl_conf.dag_max_rank_increase == dag_max_rank_increase &&
            rpl_conf.min_hop_rank_increase == min_hop_rank_increase &&
            rpl_conf.default_lifetime == default_lifetime &&
            rpl_conf.lifetime_unit == lifetime_unit) {
        // Same values no update needed
        return;
    }

    rpl_conf.dio_interval_min = imin;
    rpl_conf.dio_interval_doublings = doubling;
    rpl_conf.dio_redundancy_constant = redundancy;
    rpl_conf.dag_max_rank_increase = dag_max_rank_increase;
    rpl_conf.min_hop_rank_increase = min_hop_rank_increase;
    rpl_conf.default_lifetime = default_lifetime;
    rpl_conf.lifetime_unit = lifetime_unit;

    if (protocol_6lowpan_rpl_root_dodag) {
        rpl_control_update_dodag_config(protocol_6lowpan_rpl_root_dodag, &rpl_conf);
        ws_bbr_rpl_version_increase(cur);
    }
}

bool ws_bbr_backbone_address_get(uint8_t *address)
{
    if (backbone_interface_id < 0) {
        return false;
    }

    if (arm_net_address_get(backbone_interface_id, ADDR_IPV6_GP, address) != 0) {
        // No global prefix available
        return false;
    }

    return true;
}

static void ws_bbr_rpl_root_start(struct net_if *cur, uint8_t *dodag_id)
{
    tr_info("RPL root start");
    rpl_data_init_root();

    if (protocol_6lowpan_rpl_root_dodag) {
        rpl_control_delete_dodag_root(protocol_6lowpan_rpl_domain, protocol_6lowpan_rpl_root_dodag);
        protocol_6lowpan_rpl_root_dodag = NULL;
    }

    protocol_6lowpan_rpl_root_dodag = rpl_control_create_dodag_root(protocol_6lowpan_rpl_domain, current_instance_id, dodag_id, &rpl_conf, rpl_conf.min_hop_rank_increase, RPL_GROUNDED | RPL_MODE_NON_STORING | RPL_DODAG_PREF(0));
    if (!protocol_6lowpan_rpl_root_dodag) {
        tr_error("RPL dodag init failed");
        return;
    }
    // RPL memory limits set larger for Border router
    rpl_control_set_memory_limits(64 * 1024, 0);

    // Initial version number for RPL start is 240 from RPL RFC
    ws_bbr_rpl_version_timer_start(cur, 240);

}


static void ws_bbr_rpl_root_stop(void)
{
    tr_info("RPL root stop");
    if (protocol_6lowpan_rpl_root_dodag) {
        rpl_control_delete_dodag_root(protocol_6lowpan_rpl_domain, protocol_6lowpan_rpl_root_dodag);
        protocol_6lowpan_rpl_root_dodag = NULL;
    }
}

static if_address_entry_t *ws_bbr_slaac_generate(struct net_if *cur, uint8_t *ula_prefix)
{
    if_address_entry_t *add_entry = NULL;
    const uint8_t *address;

    address = addr_select_with_prefix(cur, ula_prefix, 64, 0);
    if (address) {
        // Address already exists for this prefix find the entry
        add_entry = addr_get_entry(cur, address);
    }

    if (!add_entry) {
        add_entry = icmpv6_slaac_address_add(cur, ula_prefix, 64, 0xffffffff, 0xffffffff, true, SLAAC_IID_FIXED);
    }
    if (!add_entry) {
        tr_error("ula create failed");
        return NULL;
    }
    // Set the timeouts for this address and policy
    icmpv6_slaac_prefix_update(cur, ula_prefix, 64, 0xffffffff, 0xffffffff);
    addr_policy_table_add_entry(ula_prefix, 64, 2, WS_NON_PREFFRED_LABEL);
    return add_entry;
}

static void ws_bbr_slaac_remove(struct net_if *cur, uint8_t *ula_prefix)
{
    if (cur) {
        icmpv6_slaac_prefix_update(cur, ula_prefix, 64, 0, 0);
    }

    addr_policy_table_delete_entry(ula_prefix, 64);
}

/*
 * 0 static non rooted self generated own address
 * 1 static address with backbone connectivity
 */
static uint8_t *ws_bbr_bb_static_prefix_get(uint8_t *dodag_id_ptr)
{

    /* Get static ULA prefix if we have configuration in backbone and there is address we use that.
     *
     * If there is no address we can use our own generated ULA as a backup ULA
     */

    struct net_if *bb_interface = protocol_stack_interface_info_get_by_id(backbone_interface_id);

    if (bb_interface) {
        ns_list_foreach(if_address_entry_t, addr, &bb_interface->ip_addresses) {
            if (!bitcmp(addr->address, bb_interface->ipv6_configure.static_prefix64, 64)) {
                // static address available in interface copy the prefix and return the address
                if (dodag_id_ptr) {
                    memcpy(dodag_id_ptr, bb_interface->ipv6_configure.static_prefix64, 8);
                }
                return addr->address;
            }
        }
    }
    return NULL;
}


static int ws_bbr_static_dodagid_create(struct net_if *cur)
{
    if (memcmp(current_dodag_id, ADDR_UNSPECIFIED, 16) != 0) {
        // address generated
        return 0;
    }

    uint8_t *static_address_ptr = ws_bbr_bb_static_prefix_get(NULL);
    if (static_address_ptr) {
        memcpy(current_dodag_id, static_address_ptr, 16);
        tr_info("BBR Static DODAGID %s", tr_ipv6(current_dodag_id));
        return 0;
    }

    // This address is only used if no other address available.
    if_address_entry_t *add_entry = ws_bbr_slaac_generate(cur, static_dodag_id_prefix);
    if (!add_entry) {
        tr_error("dodagid create failed");
        return -1;
    }
    memcpy(current_dodag_id, add_entry->address, 16);
    tr_info("BBR generate DODAGID %s", tr_ipv6(current_dodag_id));

    return 0;
}

static void ws_bbr_dodag_get(uint8_t *local_prefix_ptr, uint8_t *global_prefix_ptr)
{
    uint8_t global_address[16];

    memset(global_prefix_ptr, 0, 8);

    // By default static dodagID prefix is used as local prefix
    memcpy(local_prefix_ptr, static_dodag_prefix, 8);
    ws_bbr_bb_static_prefix_get(local_prefix_ptr);

    if (arm_net_address_get(backbone_interface_id, ADDR_IPV6_GP, global_address) != 0) {
        // No global prefix available
        return;
    }
    struct net_if *bb_interface = protocol_stack_interface_info_get_by_id(backbone_interface_id);
    if_address_entry_t *addr_entry = addr_get_entry(bb_interface, global_address);

    if (!addr_entry || addr_entry->preferred_lifetime == 0) {
        return;
    }
    //tr_debug("BBR address %s lifetime %d pref %d", tr_ipv6(addr_entry->address), addr_entry->valid_lifetime, addr_entry->preferred_lifetime);

    if (memcmp(global_address, local_prefix_ptr, 8) == 0) {
        // static prefix is same
        return;
    }
    memcpy(global_prefix_ptr, global_address, 8);
    return;
}

static void ws_bbr_routing_stop(struct net_if *cur)
{
    tr_info("BBR routing stop");
    if (memcmp(current_local_prefix, ADDR_UNSPECIFIED, 8) != 0) {
        ws_bbr_slaac_remove(cur, current_local_prefix);
        memset(current_local_prefix, 0, 8);
    }

    if (memcmp(current_global_prefix, ADDR_UNSPECIFIED, 8) != 0) {
        if (backbone_interface_id >= 0) {
            // Delete route to backbone if it exists
            ipv6_route_add_with_info(current_global_prefix, 64, backbone_interface_id, NULL, ROUTE_THREAD_BBR, NULL, 0, 0, 0);
        }
        memset(current_global_prefix, 0, 8);
    }

    if (memcmp(current_dodag_id, ADDR_UNSPECIFIED, 8) != 0) {
        ws_bbr_slaac_remove(cur, current_dodag_id);
        memset(current_dodag_id, 0, 16);
    }

    ws_bbr_rpl_root_stop();
}

static void ws_bbr_rpl_status_check(struct net_if *cur)
{

    uint8_t local_prefix[8] = {0};
    uint8_t global_prefix[8] = {0};
    uint8_t prefix_flags = 0;
    uint32_t prefix_lifetime = 0;

    //tr_info("BBR status check");

    /*
     * Start RPL Root
     */
    if (!protocol_6lowpan_rpl_root_dodag) {
        // Generate DODAGID
        if (ws_bbr_static_dodagid_create(cur) == 0) {
            ws_bbr_rpl_root_start(cur, current_dodag_id);
        }
    }

    if (!protocol_6lowpan_rpl_root_dodag) {
        // Failed to start
        tr_error("BBR failed to start");
        return;
    }

    /*
     * Check that DODAGID is still valid
     */
    if (protocol_interface_address_compare(current_dodag_id) != 0) {
        //DODAGID is lost need to restart
        tr_warn("DODAGID lost restart BBR");
        ws_bbr_routing_stop(cur);
        return;
    }

    ws_bbr_dodag_get(local_prefix, global_prefix);

    /*
     * Add default route to RPL
     */
    if (configuration & BBR_DEFAULT_ROUTE) {
        rpl_control_update_dodag_route(protocol_6lowpan_rpl_root_dodag, NULL, 0, 0, WS_ROUTE_LIFETIME, false);
    }

    /*
     * Create static ULA configuration or modify if needed
     */
    if ((configuration & BBR_ULA_C) &&
            memcmp(current_local_prefix, local_prefix, 8) != 0) {
        // Generate Static ULA
        // Start static ULA prefix and routing always
        if (memcmp(current_local_prefix, ADDR_UNSPECIFIED, 8) != 0) {
            // Remove Old ULA prefix
            ws_bbr_slaac_remove(cur, current_local_prefix);
            rpl_control_update_dodag_prefix(protocol_6lowpan_rpl_root_dodag, current_local_prefix, 64, PIO_A, 0, 0, true);
            memset(current_local_prefix, 0, 8);
        }

        if (memcmp(local_prefix, ADDR_UNSPECIFIED, 8) != 0) {
            if (!ws_bbr_slaac_generate(cur, local_prefix)) {
                // Address creation failed
                return;
            }

            tr_info("RPL Local prefix activate %s", tr_ipv6_prefix(local_prefix, 64));
            rpl_control_update_dodag_prefix(protocol_6lowpan_rpl_root_dodag, local_prefix, 64, PIO_A, WS_ULA_LIFETIME, WS_ULA_LIFETIME, false);
            memcpy(current_local_prefix, local_prefix, 8);
        }
    }

    /*
     * Check if backup ULA prefix is needed
     */
    if ((configuration & BBR_ULA_C) == 0 && memcmp(global_prefix, ADDR_UNSPECIFIED, 8) == 0) {
        //Global prefix not available count if backup ULA should be created
        uint32_t prefix_wait_time = BBR_BACKUP_ULA_DELAY;
        global_prefix_unavailable_timer += BBR_CHECK_INTERVAL;

        if (NULL != ws_bbr_bb_static_prefix_get(NULL)) {
            // If we have a static configuration we activate it faster.
            prefix_wait_time = 40;
        }

        if (global_prefix_unavailable_timer >= prefix_wait_time) {
            if (memcmp(current_global_prefix, ADDR_UNSPECIFIED, 8) == 0) {
                tr_info("start using backup prefix %s", tr_ipv6_prefix(local_prefix, 64));
            }
            memcpy(global_prefix, local_prefix, 8);
        }
    } else {
        //Global connection OK
        global_prefix_unavailable_timer = 0;
    }

    /*
     * Check for Global prefix
     */
    if (memcmp(current_global_prefix, global_prefix, 8) != 0) {
        // Global prefix changed
        if (memcmp(current_global_prefix, ADDR_UNSPECIFIED, 8) != 0) {
            // TODO remove old global prefix
            tr_info("RPL global prefix deactivate %s", tr_ipv6_prefix(current_global_prefix, 64));

            // Old backbone information is deleted after 120 seconds
            rpl_control_update_dodag_prefix(protocol_6lowpan_rpl_root_dodag, current_global_prefix, 64, 0, 0, 0, true);
            if (configuration & BBR_GUA_ROUTE) {
                rpl_control_update_dodag_route(protocol_6lowpan_rpl_root_dodag, current_global_prefix, 64, 0, 0, true);
            }
            if (backbone_interface_id >= 0) {
                ipv6_route_add_with_info(current_global_prefix, 64, backbone_interface_id, NULL, ROUTE_THREAD_BBR, NULL, 0, 120, 0);
            }
        }
        // TODO add global prefix
        if (memcmp(global_prefix, ADDR_UNSPECIFIED, 8) != 0) {
            tr_info("RPL global prefix activate %s", tr_ipv6_prefix(global_prefix, 64));
            // Add default route to RPL
            // Enable default routing to backbone
            if (backbone_interface_id >= 0) {
                if (ipv6_route_add_with_info(global_prefix, 64, backbone_interface_id, NULL, ROUTE_THREAD_BBR, NULL, 0, 0xffffffff, 0) == NULL) {
                    tr_error("global route add failed");
                    return;
                }
            }
            if (configuration & BBR_GUA_SLAAC) {
                prefix_flags |= PIO_A;
                prefix_lifetime = WS_ULA_LIFETIME;
            }

            rpl_control_update_dodag_prefix(protocol_6lowpan_rpl_root_dodag, global_prefix, 64, prefix_flags, prefix_lifetime, prefix_lifetime, false);
            // no check for failure should have

            if (configuration & BBR_GUA_ROUTE) {
                // Add also global prefix and route to RPL
                rpl_control_update_dodag_route(protocol_6lowpan_rpl_root_dodag, global_prefix, 64, 0, WS_ROUTE_LIFETIME, false);
            }

        }
        memcpy(current_global_prefix, global_prefix, 8);
        ws_bbr_rpl_version_increase(cur);
    } else if (memcmp(current_global_prefix, ADDR_UNSPECIFIED, 8) != 0) {
        /*
         *  This is a keep alive validation RPL is updated to hold the real info.
         *  There is no status checks on prefix adds so this makes sure they are not lost
         *  DHCP validation should be done also
         */
        if (configuration & BBR_GUA_SLAAC) {
            prefix_flags |= PIO_A;
            prefix_lifetime = WS_ULA_LIFETIME;
        }
        rpl_control_update_dodag_prefix(protocol_6lowpan_rpl_root_dodag, current_global_prefix, 64, prefix_flags, prefix_lifetime, prefix_lifetime, false);

        if (configuration & BBR_GUA_ROUTE) {
            // Add also global prefix and route to RPL
            rpl_control_update_dodag_route(protocol_6lowpan_rpl_root_dodag, current_global_prefix, 64, 0, WS_ROUTE_LIFETIME, false);
        }
    }
}
void ws_bbr_pan_version_increase(struct net_if *cur)
{
    if (!cur) {
        return;
    }
    tr_debug("Border router version number update");
    if (configuration & BBR_PERIODIC_VERSION_INC) {
        // Periodically increase the version number.
        // This removes need for DAO, but causes slowness in recovery
        pan_version_timer = cur->ws_info.cfg->timing.pan_timeout / PAN_VERSION_CHANGE_INTERVAL;
    } else {
        // Version number is not periodically increased forcing nodes to check Border router availability using DAO
        pan_version_timer = 0;
    }
    cur->ws_info.pan_information.pan_version++;
    // Inconsistent for border router to make information distribute faster
    ws_bootstrap_configuration_trickle_reset(cur);

    // Indicate new pan version to PAE controller
    ws_pae_controller_nw_info_set(cur, cur->ws_info.network_pan_id,
                                  cur->ws_info.pan_information.pan_version,
                                  cur->ws_info.pan_information.lpan_version,
                                  cur->ws_info.cfg->gen.network_name);
}

void ws_bbr_lpan_version_increase(struct net_if *cur)
{
    if (!cur) {
        return;
    }
    tr_debug("Border router LFN version number update");
    cur->ws_info.pan_information.lpan_version++;
    // Inconsistent for border router to make information distribute faster
    ws_bootstrap_configuration_trickle_reset(cur);

    // Indicate new pan version to PAE controller
    ws_pae_controller_nw_info_set(cur, cur->ws_info.network_pan_id,
                                  cur->ws_info.pan_information.pan_version,
                                  cur->ws_info.pan_information.lpan_version,
                                  cur->ws_info.cfg->gen.network_name);
    //   Wi-SUN FAN 1.1v06 6.3.4.6.3 FFN Discovery / Join
    // A Border Router MUST increment PAN Version (PANVER-IE) [...] when [...]
    // the following occurs:
    // d. A change in LFN Version.
    ws_bbr_pan_version_increase(cur);
}

void ws_bbr_seconds_timer(struct net_if *cur, uint32_t seconds)
{
    (void)seconds;

    if (cur->bootstrap_mode != ARM_NWK_BOOTSTRAP_MODE_6LoWPAN_BORDER_ROUTER) {
        // Not a border router
        return;
    }
    if (!cur->rpl_domain) {
        // RPL not started
        return;
    }

    if (bbr_delay_timer > seconds) {
        bbr_delay_timer -= seconds;
    } else {
        bbr_delay_timer = BBR_CHECK_INTERVAL; // 20 second interval between status checks

        // prequisists
        // Wi-SUN network configuration started without RPL

        // RPL configured simple
        // 1. Wait for backend connection
        // 2. When address becomes available in backend start RPL dodag
        // 3. if address removed remove dodag

        // RPL configured Advanced
        // 1. Add ULA DODAG and and start ROOT even without backend
        //   a. If static prefix configured use it.
        //   b. generate random ULA and publish it to backend
        // 2. if GUA prefix becomes available in backend add new prefix to DODAG
        // 3. if GUA prefix is removed remove the prefix.

        ws_bbr_rpl_status_check(cur);

    }
    // Normal BBR operation
    if (protocol_6lowpan_rpl_root_dodag) {
        /*
         * PAN version change is one way to enable nodes to detect the border router availability
         * if this is not done periodically devices need to have other means to detect border router condiftion
         *
         * If devices do not see version change they need to send DAO to border router before PAN timeout
         *
         * The update frequency should be related to PAN timeout and happen for example 4 times.
         */
        if (pan_version_timer > 0) {
            if (pan_version_timer > seconds) {
                pan_version_timer -= seconds;
            } else {
                // PAN version number update
                pan_version_timer = 0;
                ws_bbr_pan_version_increase(cur);
            }
        }
        if (cur->ws_info.rpl_version_timer > seconds) {
            cur->ws_info.rpl_version_timer -= seconds;
        } else {
            // RPL version update needed
            ws_bbr_rpl_version_increase(cur);
        }
    }
}

uint16_t test_pan_size_override = 0xffff;

uint16_t ws_bbr_pan_size(struct net_if *cur)
{
    uint16_t result = 0;

    if (!cur || !cur->rpl_domain) {
        return 0;
    }

    if (test_pan_size_override != 0xffff) {
        return test_pan_size_override;
    }
    //
    const uint8_t *prefix_ptr;
    if (memcmp(current_global_prefix, ADDR_UNSPECIFIED, 8) != 0) {
        //Use GUA Prefix
        prefix_ptr = current_global_prefix;
    } else {
        //Use ULA for indentifier
        prefix_ptr = current_local_prefix;
    }

    rpl_control_get_instance_dao_target_count(cur->rpl_domain, current_instance_id, NULL, prefix_ptr, &result);
    if (result > 0) {
        // remove the Border router from the PAN size
        result--;
    }
    return result;
}

bool ws_bbr_ready_to_start(struct net_if *cur)
{

    (void)cur;
    uint8_t global_address[16];

    if (backbone_interface_id < 0) {
        // No need to wait for backbone
        return true;
    }

    if ((configuration & BBR_BB_WAIT) != BBR_BB_WAIT) {
        // No need to wait for backbone
        return true;
    }

    if (arm_net_address_get(backbone_interface_id, ADDR_IPV6_GP, global_address) != 0) {
        // No global prefix available
        return false;
    }

    return true;
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

uint16_t ws_bbr_bsi_generate(struct net_if *interface)
{
    (void) interface;
    //Give current one
    uint16_t bsi = ws_bbr_fhss_bsi;
    //Update value for next round
    ws_bbr_fhss_bsi++;
    //Store To NVN
    ws_bbr_nvm_info_write(ws_bbr_fhss_bsi, ws_bbr_pan_id);
    return bsi;
}

uint16_t ws_bbr_pan_id_get(struct net_if *interface)
{
    (void) interface;
    return ws_bbr_pan_id;
}

/* Public APIs
 *
 */

int ws_bbr_start(int8_t interface_id, int8_t bb_interface_id)
{
    (void)interface_id;
    struct net_if *bb_interface = protocol_stack_interface_info_get_by_id(bb_interface_id);

    if (!bb_interface) {
        return -1;
    }
    // TODO make bb configurations

    backbone_interface_id = bb_interface_id;

    return 0;
}

void ws_bbr_stop(int8_t interface_id)
{
    struct net_if *cur = protocol_stack_interface_info_get_by_id(interface_id);

    ws_bbr_routing_stop(cur);
    backbone_interface_id = -1;
    current_instance_id++;
}

int ws_bbr_configure(int8_t interface_id, uint16_t options)
{
    struct net_if *cur = protocol_stack_interface_info_get_by_id(interface_id);

    if (options == configuration) {
        return 0;
    }
    //Configuration changed
    configuration = options;
    if (protocol_6lowpan_rpl_root_dodag) {
        // Already active needs to restart
        ws_bbr_routing_stop(cur);
        ws_bbr_pan_version_increase(cur);
        ws_bbr_lpan_version_increase(cur);
    }
    return 0;
}

int ws_bbr_info_get(int8_t interface_id, bbr_information_t *info_ptr)
{
    struct net_if *cur = protocol_stack_interface_info_get_by_id(interface_id);
    rpl_dodag_info_t dodag_info;

    if (!info_ptr) {
        return -1;
    }
    if (!cur || !protocol_6lowpan_rpl_root_dodag) {
        tr_warn("bbr not started");
        return -1;
    }
    struct rpl_instance *instance = rpl_control_lookup_instance(protocol_6lowpan_rpl_domain, current_instance_id, current_dodag_id);
    if (!instance) {
        tr_warn("bbr instance not found");
        return -2;
    }
    // Zero the structure
    memset(info_ptr, 0, sizeof(bbr_information_t));

    rpl_control_read_dodag_info(instance, &dodag_info);

    memcpy(info_ptr->dodag_id, current_dodag_id, 16);
    memcpy(info_ptr->prefix, current_global_prefix, 8);

    // Get the Wi-SUN interface generated address that is used in the RF interface.
    const uint8_t *wisun_if_addr = addr_select_with_prefix(cur, current_global_prefix, 64, SOCKET_IPV6_PREFER_SRC_PUBLIC);

    if (wisun_if_addr) {
        memcpy(info_ptr->IID, wisun_if_addr + 8, 8);
    }

    ipv6_route_t *next_hop = ipv6_route_choose_next_hop(ADDR_6TO4, backbone_interface_id, NULL);
    if (next_hop) {
        memcpy(info_ptr->gateway, next_hop->info.next_hop_addr, 16);
    }

    info_ptr->devices_in_network = ws_bbr_pan_size(cur);
    info_ptr->instance_id = current_instance_id;
    info_ptr->version = dodag_info.version_num;
    info_ptr->timestamp = g_monotonic_time_100ms; // TODO switch to second timer
    // consider DTSN included It can also be added for getting device information
    // Consider own device API to get DTSN, DHCP lifetime values
    return 0;
}

int ws_bbr_routing_table_get(int8_t interface_id, bbr_route_info_t *table_ptr, uint16_t table_len)
{
    struct net_if *cur = protocol_stack_interface_info_get_by_id(interface_id);
    int length;

    if (!cur || !protocol_6lowpan_rpl_root_dodag) {
        return -1;
    }

    struct rpl_instance *instance = rpl_control_lookup_instance(protocol_6lowpan_rpl_domain, current_instance_id, current_dodag_id);
    if (!instance) {
        tr_warn("bbr instance not found");
        return -2;
    }
    memset(table_ptr, 0, table_len);

    /* RPL structure must match the external structure so we dont need to make conversion.
     *
     */
    length = rpl_control_route_table_get(instance, current_global_prefix, (rpl_route_info_t *)table_ptr, table_len);

    return length;
}

int ws_bbr_node_keys_remove(int8_t interface_id, uint8_t *eui64)
{
    return ws_pae_controller_node_keys_remove(interface_id, eui64);
}

int ws_bbr_node_access_revoke_start(int8_t interface_id, bool is_lgtk, uint8_t new_gtk[GTK_LEN])
{
    return ws_pae_controller_node_access_revoke_start(interface_id, is_lgtk, new_gtk);
}

int ws_bbr_eapol_node_limit_set(int8_t interface_id, uint16_t limit)
{
    return ws_pae_controller_node_limit_set(interface_id, limit);
}

int ws_bbr_ext_certificate_validation_set(int8_t interface_id, uint8_t validation)
{
    bool enabled = false;
    if (validation & BBR_CRT_EXT_VALID_WISUN) {
        enabled = true;
    }
    return ws_pae_controller_ext_certificate_validation_set(interface_id, enabled);
}

int ws_bbr_rpl_parameters_set(int8_t interface_id, uint8_t dio_interval_min, uint8_t dio_interval_doublings, uint8_t dio_redundancy_constant)
{
    struct net_if *cur = protocol_stack_interface_info_get_by_id(interface_id);
    ws_bbr_cfg_t cfg;

    if (ws_cfg_bbr_get(&cfg) < 0) {
        return -1;
    }

    if (dio_interval_min > 0) {
        cfg.dio_interval_min = dio_interval_min;
    }
    if (dio_interval_doublings > 0) {
        cfg.dio_interval_doublings = dio_interval_doublings;
    }
    if (dio_redundancy_constant != 0xff) {
        cfg.dio_redundancy_constant = dio_redundancy_constant;
    }

    if (ws_cfg_bbr_set(cur, &cfg, 0) < 0) {
        return -2;
    }

    return 0;
}

int ws_bbr_rpl_parameters_get(int8_t interface_id, uint8_t *dio_interval_min, uint8_t *dio_interval_doublings, uint8_t *dio_redundancy_constant)
{
    ws_bbr_cfg_t cfg;

    (void) interface_id;
    if (!dio_interval_min || !dio_interval_doublings || !dio_redundancy_constant) {
        return -1;
    }

    if (ws_cfg_bbr_get(&cfg) < 0) {
        return -2;
    }

    *dio_interval_min = cfg.dio_interval_min;
    *dio_interval_doublings = cfg.dio_interval_doublings;
    *dio_redundancy_constant = cfg.dio_redundancy_constant;

    return 0;
}

int ws_bbr_rpl_parameters_validate(int8_t interface_id, uint8_t dio_interval_min, uint8_t dio_interval_doublings, uint8_t dio_redundancy_constant)
{
    ws_bbr_cfg_t cfg;

    (void) interface_id;
    if (ws_cfg_bbr_get(&cfg) < 0) {
        return -2;
    }

    if (dio_interval_min > 0) {
        cfg.dio_interval_min = dio_interval_min;
    }
    if (dio_interval_doublings > 0) {
        cfg.dio_interval_doublings = dio_interval_doublings;
    }
    if (dio_redundancy_constant != 0xff) {
        cfg.dio_redundancy_constant = dio_redundancy_constant;
    }

    if (ws_cfg_bbr_validate(&cfg) < 0) {
        return -3;
    }

    return 0;
}

int ws_bbr_bsi_set(int8_t interface_id, uint16_t new_bsi)
{
    struct net_if *cur = protocol_stack_interface_info_get_by_id(interface_id);

    //Check if new value is different than current active
    if (cur && cur->lowpan_info & INTERFACE_NWK_ACTIVE) {
        if (cur->ws_info.hopping_schedule.fhss_bsi == new_bsi) {
            return 0;
        }
        tr_debug("New BSI %u to delayed activate", new_bsi);
        ws_bootstrap_restart_delayed(cur->id);
    }

    ws_bbr_nvm_info_write(ws_bbr_fhss_bsi, ws_bbr_pan_id);
    ws_bbr_fhss_bsi = new_bsi;
    return 0;
}

int ws_bbr_pan_configuration_set(int8_t interface_id, uint16_t pan_id)
{
    if (ws_bbr_pan_id != pan_id) {
        ws_bbr_pan_id = pan_id;
        // Store to NVM and restart bootstrap
        ws_bbr_nvm_info_write(ws_bbr_fhss_bsi, ws_bbr_pan_id);
        ws_bootstrap_restart_delayed(interface_id);
    }
    return 0;
}

int ws_bbr_pan_configuration_get(int8_t interface_id, uint16_t *pan_id)
{
    (void) interface_id;
    if (!pan_id) {
        return -1;
    }

    *pan_id = ws_bbr_pan_id;

    return 0;
}

int ws_bbr_pan_configuration_validate(int8_t interface_id, uint16_t pan_id)
{
    (void) interface_id;
    (void) pan_id;
    return 0;
}

int ws_bbr_eapol_relay_get_socket_fd()
{
    return ws_bootstrap_6lbr_eapol_relay_get_socket_fd();
}

int ws_bbr_eapol_auth_relay_get_socket_fd()
{
    return ws_bootstrap_6lbr_eapol_auth_relay_get_socket_fd();

}

void ws_bbr_eapol_relay_socket_cb(int fd)
{
    ws_bootstrap_6lbr_eapol_relay_socket_cb(fd);
}

void ws_bbr_eapol_auth_relay_socket_cb(int fd)
{
    ws_bootstrap_6lbr_eapol_auth_relay_socket_cb(fd);
}

int ws_bbr_radius_address_set(int8_t interface_id, const struct sockaddr_storage *address)
{
    return ws_pae_controller_radius_address_set(interface_id, address);
}

int ws_bbr_radius_address_get(int8_t interface_id, struct sockaddr_storage *address)
{
    return ws_pae_controller_radius_address_get(interface_id, address);
}

int ws_bbr_radius_shared_secret_set(int8_t interface_id, const uint16_t shared_secret_len, const uint8_t *shared_secret)
{
    return ws_pae_controller_radius_shared_secret_set(interface_id, shared_secret_len, shared_secret);
}

int ws_bbr_radius_shared_secret_get(int8_t interface_id, uint16_t *shared_secret_len, uint8_t *shared_secret)
{
    return ws_pae_controller_radius_shared_secret_get(interface_id, shared_secret_len, shared_secret);
}

int ws_bbr_radius_timing_set(int8_t interface_id, bbr_radius_timing_t *timing)
{
    return ws_pae_controller_radius_timing_set(interface_id, timing);
}

int ws_bbr_radius_timing_get(int8_t interface_id, bbr_radius_timing_t *timing)
{
    return ws_pae_controller_radius_timing_get(interface_id, timing);
}

int ws_bbr_radius_timing_validate(int8_t interface_id, bbr_radius_timing_t *timing)
{
    return ws_pae_controller_radius_timing_validate(interface_id, timing);
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
