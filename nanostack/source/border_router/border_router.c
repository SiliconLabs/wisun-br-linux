/*
 * Copyright (c) 2012-2018, 2020, Pelion and affiliates.
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

#include "nsconfig.h"
#include "ns_types.h"
#include "string.h"
#include "ns_trace.h"
#include "nsdynmemLIB.h"
#include "nwk_interface/protocol.h"
#include "nwk_interface/protocol_timer.h"
#include "6lowpan/bootstraps/protocol_6lowpan.h"
#include "6lowpan/bootstraps/protocol_6lowpan_bootstrap.h"
#include "mac_api.h"

#include "rpl/rpl_control.h"
#include "6lowpan/nd/nd_router_object.h"
#include "service_libs/whiteboard/whiteboard.h"
#include "service_libs/blacklist/blacklist.h"
#include "service_libs/nd_proxy/nd_proxy.h"
#include "service_libs/mac_neighbor_table/mac_neighbor_table.h"
#include "shalib.h"

#ifdef ECC
#include "libX509_V3.h"
#include "ecc.h"
#endif
#include "security/tls/tls_lib.h"
#include "security/common/sec_lib.h"
#include "net_nvm_api.h"
#include "common_protocols/ipv6.h"
#include "common_protocols/icmpv6.h"
#include "common_protocols/icmpv6_prefix.h"
#include "common_protocols/icmpv6_radv.h"
#include "ipv6_stack/protocol_ipv6.h"
#include "common_functions.h"
#include "net_thread_test.h"
#include "border_router/border_router.h"
#include "6lowpan/mac/mac_helper.h"
#include "6lowpan/nvm/nwk_nvm.h"
#include "net_lib/src/net_load_balance_internal.h"
#include "6lowpan/lowpan_adaptation_interface.h"
#include "6lowpan/fragmentation/cipv6_fragmenter.h"

#ifdef HAVE_6LOWPAN_BORDER_ROUTER

#define TRACE_GROUP_BORDER_ROUTER  "br"

#define TRACE_GROUP  "br"


static int8_t border_router_nd_abro_periodically_update_by_stack(nd_router_setup_t *nd_router_configuration);

void nd_border_router_setup_refresh(nwk_interface_id id, bool fresh_abro)
{
    uint8_t *ptr = 0;
    nd_router_t *nd_router_object;
    nd_router_setup_t *nd_configure;
    protocol_interface_info_entry_t *cur_interface;
    uint8_t nd_options[30];

    cur_interface = protocol_stack_interface_info_get(id);
    if (!cur_interface) {
        return;
    } else if (cur_interface->bootstrap_mode != ARM_NWK_BOOTSTRAP_MODE_6LoWPAN_BORDER_ROUTER) {
        return;
    } else if (cur_interface->border_router_setup == 0) {
        return;
    } else if (!cur_interface->border_router_setup->nd_nwk) {
        return;
    } else if (!cur_interface->border_router_setup->nd_border_router_configure) {
        return;
    }

    nd_router_object = cur_interface->border_router_setup->nd_nwk;
    nd_configure = cur_interface->border_router_setup->nd_border_router_configure;
    nd_router_object->life_time = nd_configure->life_time;

    if (!ns_list_is_empty(&nd_router_object->prefix_list)) {
        tr_debug("Release Prefix");
        icmpv6_prefix_list_free(&nd_router_object->prefix_list);
    }

    if (!ns_list_is_empty(&nd_router_object->context_list)) {
        tr_info("Release Context");
        lowpan_context_list_free(&nd_router_object->context_list);
    }

    if (!ns_list_is_empty(&nd_configure->context_list)) {
        tr_info("Refresh Contexts");
        ns_list_foreach(lowpan_context_t, cur, &nd_configure->context_list) {
            uint8_t cid_flags = cur->cid | (cur->compression ? LOWPAN_CONTEXT_C : 0);
            uint16_t lifetime_mins = (cur->lifetime + 599) / 600;
            /* Update contexts in our ABRO advertising storage */
            lowpan_context_update(&nd_router_object->context_list, cid_flags, lifetime_mins, cur->prefix, cur->length, true);
            /* And contexts used by the interface itself (we don't hear our own adverts) */
            lowpan_context_update(&cur_interface->lowpan_contexts, cid_flags, lifetime_mins, cur->prefix, cur->length, true);
        }
    }
    /* Set Prefixs */
    if (!ns_list_is_empty(&nd_configure->prefix_list)) {
        tr_info("Refresh Prefixs");
        ns_list_foreach(prefix_entry_t, cur, &nd_configure->prefix_list) {
            ptr = nd_options;
            *ptr++ = cur->prefix_len; //Prefix Len
            *ptr++ = cur->options;   //Autonomous address enabled
            ptr = common_write_32_bit(cur->lifetime, ptr);
            ptr = common_write_32_bit(cur->preftime, ptr);
            ptr = common_write_32_bit(0, ptr); //Reserved

            memcpy(ptr, cur->prefix, 16);
            icmp_nd_router_prefix_update(nd_options, nd_router_object, cur_interface);
        }
    }

    //Update version num

    if (fresh_abro) {
        if (border_router_nd_abro_periodically_update_by_stack(nd_configure) == 0) {
            tr_info("ABRO Update and NVM operation OK");
        }
    }

    nd_router_object->abro_version_num = nd_configure->abro_version_num;
}

int8_t arm_nwk_6lowpan_border_route_nd_default_prefix_timeout_set(int8_t interface_id, uint32_t time)
{
    int8_t ret_val = -1;
    protocol_interface_info_entry_t *cur = 0;
    cur = protocol_stack_interface_info_get_by_id(interface_id);
    if (cur) {
        uint8_t *nd_options = ns_dyn_mem_temporary_alloc(30);
        if (nd_options) {
            uint8_t *ptr;
            ptr = nd_options;

            ptr = common_write_16_bit(0x4040, ptr); //Prefix Len + Autonomous address enabled
            ptr = common_write_32_bit(time, ptr);
            ptr = common_write_32_bit(time, ptr);
            memcpy(ptr, cur->border_router_setup->border_router_gp_adr, 8);
            ptr += 8;
            memset(ptr, 0, 8);
            ret_val = icmp_nd_router_prefix_proxy_update(nd_options, cur->border_router_setup->nd_border_router_configure);
            ns_dyn_mem_free(nd_options);
        }
    }
    return ret_val;
}

int8_t arm_nwk_6lowpan_border_router_context_update(int8_t interface_id, uint8_t c_id_flags, uint8_t context_len, uint16_t ttl, const uint8_t *context_ptr)
{
    int8_t ret_val = -2;
    protocol_interface_info_entry_t *cur = 0;
    cur = protocol_stack_interface_info_get_by_id(interface_id);
    if (cur) {
        ret_val = 0;
        if (cur->bootstrap_mode != ARM_NWK_BOOTSTRAP_MODE_6LoWPAN_BORDER_ROUTER) {
            ret_val = -4;
        } else if (cur->border_router_setup == 0) {
            ret_val = -3;
        } else {
            if (c_id_flags < 0x20 && context_len >= 64) {
                if (cur->border_router_setup->nd_nwk) {
                    nd_router_setup_t *routerSetup = cur->border_router_setup->nd_border_router_configure;

                    if (!lowpan_context_get_by_id(&routerSetup->context_list, (c_id_flags & LOWPAN_CONTEXT_CID_MASK))) {
                        if (ns_list_count(&routerSetup->context_list) >= ND_MAX_PROXY_CONTEXT_COUNT) {
                            return -1;
                        }
                    }

                    if (lowpan_context_update(&routerSetup->context_list, c_id_flags, ttl, context_ptr, context_len, true) != 0) {
                        ret_val = -2;
                    } else {
                        ret_val = 0;
                    }
                }
            } else {
                ret_val = -3;
            }
        }
    }
    return ret_val;
}

int8_t arm_nwk_6lowpan_border_router_nd_context_load(int8_t interface_id, uint8_t *contex_data)
{
    int8_t ret_val = -2;
    protocol_interface_info_entry_t *cur = 0;
    cur = protocol_stack_interface_info_get_by_id(interface_id);
    if (cur) {
        ret_val = 0;
        if (cur->bootstrap_mode != ARM_NWK_BOOTSTRAP_MODE_6LoWPAN_BORDER_ROUTER) {
            ret_val = -4;
        } else if (cur->border_router_setup == 0) {
            ret_val = -3;
        } else {
            uint8_t c_id;
            uint16_t lifetime;
            nd_router_setup_t *nd_router_setup;
            uint8_t con_len = *contex_data++;

            nd_router_setup = cur->border_router_setup->nd_border_router_configure;

            c_id = *contex_data++ & 0x1f; // ignore reserved fields
            lifetime = common_read_16_bit(contex_data);
            contex_data += 2;
            //Now Pointer Indicate to prefix
            //Check first is current ID at list
            if (!lowpan_context_get_by_id(&nd_router_setup->context_list, (c_id & LOWPAN_CONTEXT_CID_MASK))) {
                if (ns_list_count(&nd_router_setup->context_list) >= ND_MAX_PROXY_CONTEXT_COUNT) {
                    tr_debug("All Contexts are allocated");
                    return -1;
                }
            }
            return lowpan_context_update(&nd_router_setup->context_list, c_id, lifetime, contex_data, con_len, true);

        }
    }
    return ret_val;
}


//int8_t border_router_nd_configure_update(void)
int8_t arm_nwk_6lowpan_border_router_configure_push(int8_t interface_id)
{
    int8_t ret_val = -1;
    protocol_interface_info_entry_t *cur_interface;
    cur_interface = protocol_stack_interface_info_get_by_id(interface_id);
    if (cur_interface) {
        ret_val = 0;
        if (cur_interface->bootstrap_mode != ARM_NWK_BOOTSTRAP_MODE_6LoWPAN_BORDER_ROUTER) {
            ret_val = -4;
        } else if (cur_interface->border_router_setup == 0) {
            ret_val = -3;
        } else if ((cur_interface->lowpan_info & INTERFACE_NWK_ACTIVE) == 0) {
            ret_val = -2;
        } else {
            cur_interface->border_router_setup->nd_nwk->nd_timer = 1;
            cur_interface->border_router_setup->nd_nwk->nd_re_validate = 1;
            cur_interface->border_router_setup->nd_nwk->abro_version_num++;
            ret_val = 0;
        }
    }
    return ret_val;
}

int8_t arm_nwk_6lowpan_border_router_context_remove_by_id(int8_t interface_id, uint8_t c_id)
{
    lowpan_context_t *entry;
    protocol_interface_info_entry_t *cur_interface = 0;
    nd_router_setup_t *nd_router_configuration = 0;
    cur_interface = protocol_stack_interface_info_get_by_id(interface_id);
    if (!cur_interface) {
        return -1;
    }

    if (cur_interface->bootstrap_mode != ARM_NWK_BOOTSTRAP_MODE_6LoWPAN_BORDER_ROUTER) {
        return -4;
    }

    if (cur_interface->border_router_setup == 0) {
        return -3;
    }

    nd_router_configuration = cur_interface->border_router_setup->nd_border_router_configure;

    entry = lowpan_context_get_by_id(&nd_router_configuration->context_list, c_id);
    if (entry) {
        ns_list_remove(&nd_router_configuration->context_list, entry);
        ns_dyn_mem_free(entry);
    }
    return 0;
}

int8_t arm_nwk_6lowpan_border_router_context_parameter_update(int8_t interface_id, uint8_t c_id, uint8_t compress_mode, uint16_t ttl)
{
    protocol_interface_info_entry_t *cur_interface;
    nd_router_setup_t *nd_router_configuration;
    lowpan_context_t *entry;
    cur_interface = protocol_stack_interface_info_get_by_id(interface_id);
    if (!cur_interface) {
        return -1;
    }

    if (cur_interface->bootstrap_mode != ARM_NWK_BOOTSTRAP_MODE_6LoWPAN_BORDER_ROUTER) {
        return -4;
    }

    if (cur_interface->border_router_setup == 0) {
        return -3;
    }

    nd_router_configuration = cur_interface->border_router_setup->nd_border_router_configure;

    entry = lowpan_context_get_by_id(&nd_router_configuration->context_list, c_id);
    if (entry) {
        uint8_t cid_flag = entry->cid;
        entry->compression = compress_mode;
        entry->lifetime = ttl;
        cid_flag |= (entry->compression ? LOWPAN_CONTEXT_C : 0);
        return 0;
    }
    return -1;
}

static int8_t border_router_nd_abro_periodically_update_by_stack(nd_router_setup_t *nd_router_configuration)
{
    int8_t ret_val = -1;
    if (nd_router_configuration) {
        nd_router_configuration->abro_version_num++;
        ret_val = 0;
    }
    return ret_val;
}

#else

int8_t arm_nwk_6lowpan_border_router_context_parameter_update(int8_t interface_id, uint8_t c_id,
                                                              uint8_t compress_mode, uint16_t ttl)
{
    (void) interface_id;
    (void) c_id;
    (void) compress_mode;
    (void) ttl;
    return -1;
}

int8_t arm_nwk_6lowpan_border_router_context_remove_by_id(int8_t interface_id, uint8_t c_id)
{
    (void) interface_id;
    (void) c_id;
    return -1;
}

int8_t arm_nwk_6lowpan_border_router_configure_push(int8_t interface_id)
{
    (void) interface_id;
    return -1;
}

int8_t arm_nwk_6lowpan_border_router_nd_context_load(int8_t interface_id, uint8_t *contex_data)
{
    (void) interface_id;
    (void) contex_data;
    return -1;
}

int8_t arm_nwk_6lowpan_border_router_context_update(int8_t interface_id, uint8_t c_id_flags, uint8_t context_len, uint16_t ttl, const uint8_t *context_ptr)
{
    (void) interface_id;
    (void) c_id_flags;
    (void) context_len;
    (void) ttl;
    (void) context_ptr;
    return -1;
}

int8_t arm_nwk_6lowpan_border_route_nd_default_prefix_timeout_set(int8_t interface_id, uint32_t time)
{
    (void) interface_id;
    (void) time;
    return -1;
}

#endif
