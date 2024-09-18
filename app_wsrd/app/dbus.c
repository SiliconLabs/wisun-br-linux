/*
 * SPDX-License-Identifier: LicenseRef-MSLA
 * Copyright (c) 2024 Silicon Laboratories Inc. (www.silabs.com)
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
#include <systemd/sd-bus.h>
#include <errno.h>

#include "common/crypto/ws_keys.h"
#include "common/memutils.h"
#include "app_wsrd/ipv6/ipv6_addr_mc.h"
#include "app_wsrd/app/wsrd.h"

#include "dbus.h"

static int dbus_join_multicast_group(sd_bus_message *m, void *userdata, sd_bus_error *ret_error)
{
    struct ipv6_ctx *ipv6 = userdata;
    const struct in6_addr *addr;
    size_t len;
    int ret;

    sd_bus_message_read_array(m, 'y', (const void **)&addr, &len);
    if (len != 16  || !IN6_IS_ADDR_MULTICAST(addr))
        return sd_bus_error_set_errno(ret_error, EINVAL);

    ret = ipv6_addr_add_mc(ipv6, addr);
    if (ret < 0) {
        WARN("%s: %s", __func__, strerror(-ret));
        return sd_bus_error_set_errno(ret_error, -ret);
    }
    sd_bus_reply_method_return(m, NULL);
    return 0;
}

int dbus_leave_multicast_group(sd_bus_message *m, void *userdata, sd_bus_error *ret_error)
{
    struct ipv6_ctx *ipv6 = userdata;
    const struct in6_addr *addr;
    size_t len;
    int ret;

    sd_bus_message_read_array(m, 'y', (const void **)&addr, &len);
    if (len != 16 || !IN6_IS_ADDR_MULTICAST(addr))
        return sd_bus_error_set_errno(ret_error, EINVAL);

    ret = ipv6_addr_del_mc(ipv6, addr);
    if (ret < 0) {
        WARN("%s: %s", __func__, strerror(-ret));
        return sd_bus_error_set_errno(ret_error, -ret);
    }
    sd_bus_reply_method_return(m, NULL);
    return 0;
}

static int dbus_get_dodag_id(sd_bus *bus, const char *path, const char *interface,
                             const char *property, sd_bus_message *reply,
                             void *userdata, sd_bus_error *ret_error)
{
    struct ipv6_ctx *ipv6 = userdata;
    struct ipv6_neigh *parent;

    parent = rpl_neigh_pref_parent(ipv6);
    if (!parent)
        return sd_bus_error_set_errno(ret_error, EAGAIN);
    sd_bus_message_append_array(reply, 'y', parent->rpl->dio.dodag_id.s6_addr,
                                sizeof(parent->rpl->dio.dodag_id.s6_addr));
    return 0;
}

// Experimental property, will be removed in the future.
// FIXME: drop once the 'Nodes' property is available.
static int dbus_get_primary_parent(sd_bus *bus, const char *path, const char *interface,
                                   const char *property, sd_bus_message *reply,
                                   void *userdata, sd_bus_error *ret_error)
{
    struct ipv6_ctx *ipv6 = userdata;
    struct ipv6_neigh *parent;

    parent = rpl_neigh_pref_parent(ipv6);
    if (!parent || !parent->rpl || !parent->rpl->dao_ack_received)
        return sd_bus_error_set_errno(ret_error, EAGAIN);
    sd_bus_message_append_array(reply, 'y', parent->gua.s6_addr,
                                sizeof(parent->gua.s6_addr));
    return 0;
}

static int dbus_get_pan_version(sd_bus *bus, const char *path, const char *interface,
                                const char *property, sd_bus_message *reply,
                                void *userdata, sd_bus_error *ret_error)
{
    int pan_version = *(int *)userdata;

    if (pan_version < 0)
        return sd_bus_error_set_errno(ret_error, EAGAIN);
    sd_bus_message_append_basic(reply, 'q', userdata);
    return 0;
}

static int dbus_get_gaks(sd_bus *bus, const char *path, const char *interface,
                         const char *property, sd_bus_message *reply,
                         void *userdata, sd_bus_error *ret_error)
{
    struct wsrd *wsrd = userdata;
    uint8_t gak[16];

    sd_bus_message_open_container(reply, 'a', "ay");
    for (int i = 0; i < 4; i++) {
        ws_generate_gak(wsrd->config.ws_netname, wsrd->supp.gtks[i].gtk, gak);
        sd_bus_message_append_array(reply, 'y', gak, sizeof(gak));
    }
    sd_bus_message_close_container(reply);
    return 0;
}

static int dbus_get_pan_id(sd_bus *bus, const char *path, const char *interface,
                           const char *property, sd_bus_message *reply,
                           void *userdata, sd_bus_error *ret_error)
{
    sd_bus_message_append_basic(reply, 'q', userdata);
    return 0;
}

static int dbus_get_hw_address(sd_bus *bus, const char *path, const char *interface,
                               const char *property, sd_bus_message *reply,
                               void *userdata, sd_bus_error *ret_error)
{
    uint8_t *hw_addr = userdata;

    sd_bus_message_append_array(reply, 'y', hw_addr, 8);
    return 0;
}

const struct sd_bus_vtable wsrd_dbus_vtable[] = {
    SD_BUS_VTABLE_START(0),
    SD_BUS_METHOD_WITH_OFFSET("JoinMulticastGroup",  "ay", NULL, dbus_join_multicast_group,  offsetof(struct wsrd, ipv6), 0),
    SD_BUS_METHOD_WITH_OFFSET("LeaveMulticastGroup", "ay", NULL, dbus_leave_multicast_group, offsetof(struct wsrd, ipv6), 0),
    SD_BUS_PROPERTY("HwAddress",     "ay",  dbus_get_hw_address,     offsetof(struct wsrd, ws.rcp.eui64), 0),
    SD_BUS_PROPERTY("PanId",         "q",   dbus_get_pan_id,         offsetof(struct wsrd, ws.pan_id),      SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
    SD_BUS_PROPERTY("Gaks",          "aay", dbus_get_gaks,           0,                                     SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
    SD_BUS_PROPERTY("PanVersion",    "q",   dbus_get_pan_version,    offsetof(struct wsrd, ws.pan_version), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
    SD_BUS_PROPERTY("PrimaryParent", "ay",  dbus_get_primary_parent, offsetof(struct wsrd, ipv6),           SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
    SD_BUS_PROPERTY("DodagId",       "ay",  dbus_get_dodag_id,       offsetof(struct wsrd, ipv6),           0),
    SD_BUS_VTABLE_END,
};
