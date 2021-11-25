/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
#include <errno.h>
#include <systemd/sd-bus.h>

#include "nsconfig.h"
#include "nanostack/source/6LoWPAN/ws/ws_common.h"
#include "nanostack/source/6LoWPAN/ws/ws_pae_controller.h"
#include "nanostack/source/6LoWPAN/ws/ws_cfg_settings.h"
#include "nanostack/source/NWK_INTERFACE/Include/protocol.h"
#include "nanostack/source/Security/protocols/sec_prot_keys.h"
#include "nanostack/source/Common_Protocols/icmpv6.h"

#include "nanostack/ws_bbr_api.h"
#include "nanostack/socket_api.h"
#include "mbed-client-libservice/ip6string.h"

#include "host-common/utils.h"
#include "host-common/log.h"
#include "named_values.h"
#include "dbus.h"
#include "wsbr.h"

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
}


static void print_ping_reply(void *cb)
{
    socket_callback_t *event = (socket_callback_t *)cb;
    ns_address_t src_addr;
    char src[48];
    uint8_t data[256];
    int len;

    len = socket_recvfrom(event->socket_id, data, sizeof(data), 0, &src_addr);
    ip6tos(src_addr.address, src);
    DEBUG("if %d, socket %d, event %2X from %s, %d/%d bytes", event->interface_id,
          event->socket_id, event->event_type, src, event->d_len, len);
}

static int dbus_debug_ping(sd_bus_message *m, void *userdata, sd_bus_error *ret_error)
{
    struct wsbr_ctxt *ctxt = userdata;
    const char *ipv6str;
    struct ns_address dest_addr = {
        .type = ADDRESS_IPV6,
    };
    uint8_t payload[8] = { ICMPV6_TYPE_INFO_ECHO_REQUEST, };
    int16_t multicast_hop_limit = 64;
    int ret;

    ret = sd_bus_message_read(m, "s", &ipv6str);
    if (ret < 0)
        return sd_bus_error_set_errno(ret_error, -ret);
    ret = stoip6(ipv6str, strlen(ipv6str), dest_addr.address);
    if (!ret)
        return sd_bus_error_set_errno(ret_error, EINVAL);
    if (ctxt->ping_socket_fd >= 0)
        socket_close(ctxt->ping_socket_fd);
    ctxt->ping_socket_fd = socket_open(SOCKET_ICMP, 0, print_ping_reply);
    if (ctxt->ping_socket_fd < 0)
        return sd_bus_error_set_errno(ret_error, EINVAL);
    ret = socket_setsockopt(ctxt->ping_socket_fd, SOCKET_IPPROTO_IPV6, SOCKET_IPV6_MULTICAST_HOPS, &multicast_hop_limit, sizeof(multicast_hop_limit));
    if (ret < 0)
        return sd_bus_error_set_errno(ret_error, EINVAL);
    ret = socket_sendto(ctxt->ping_socket_fd, &dest_addr, payload, sizeof(payload));
    if (ret < 0)
        return sd_bus_error_set_errno(ret_error, EINVAL);
    sd_bus_reply_method_return(m, NULL);
    return 0;
}

static int dbus_get_gtks(sd_bus *bus, const char *path, const char *interface,
                         const char *property, sd_bus_message *reply,
                         void *userdata, sd_bus_error *ret_error)
{
    int interface_id = *(int *)userdata;
    sec_prot_gtk_keys_t *gtks = ws_pae_controller_get_gtks(interface_id);
    int ret, i;

    if (!gtks)
        return sd_bus_error_set_errno(ret_error, EBADR);
    ret = sd_bus_message_open_container(reply, 'a', "ay");
    WARN_ON(ret < 0, "%s", strerror(-ret));
    for (i = 0; i < ARRAY_SIZE(gtks->gtk); i++) {
        ret = sd_bus_message_append_array(reply, 'y', gtks->gtk[i].key, ARRAY_SIZE(gtks->gtk[i].key));
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
    int interface_id = *(int *)userdata;
    protocol_interface_info_entry_t *interface_ptr = protocol_stack_interface_info_get_by_id(interface_id);
    sec_prot_gtk_keys_t *gtks = ws_pae_controller_get_gtks(interface_id);
    uint8_t gak[16];
    int ret, i;

    if (!gtks || !interface_ptr || !interface_ptr->ws_info || !interface_ptr->ws_info->cfg)
        return sd_bus_error_set_errno(ret_error, EBADR);
    ret = sd_bus_message_open_container(reply, 'a', "ay");
    WARN_ON(ret < 0, "%s", strerror(-ret));
    for (i = 0; i < ARRAY_SIZE(gtks->gtk); i++) {
        // GAK is SHA256 of network name concatened with GTK
        ws_pae_controller_gak_from_gtk(gak, gtks->gtk[i].key, interface_ptr->ws_info->cfg->gen.network_name);
        ret = sd_bus_message_append_array(reply, 'y', gak, ARRAY_SIZE(gak));
        WARN_ON(ret < 0, "%s", strerror(-ret));
    }
    ret = sd_bus_message_close_container(reply);
    WARN_ON(ret < 0, "%s", strerror(-ret));
    return 0;
}


static int dbus_root_certificate_add(sd_bus_message *m, void *userdata, sd_bus_error *ret_error)
{
    arm_certificate_entry_s cert = { };
    const char *content;
    int ret;

    ret = sd_bus_message_read(m, "s", &content);
    if (ret < 0)
        return sd_bus_error_set_errno(ret_error, -ret);
    cert.cert = (uint8_t *)strdup(content);
    /* mbedtls expects a \0 at the end of PEM certificate (but not on end of DER
     * certificates). Since this API use a string as input the argument cannot
     * be in DER format. So, add '\0' unconditionally.
     */
    cert.cert_len = strlen(content) + 1;
    ret = arm_network_trusted_certificate_add(&cert);
    if (ret < 0)
        return sd_bus_error_set_errno(ret_error, EINVAL);

    sd_bus_reply_method_return(m, NULL);
    return 0;
}

static int dbus_root_certificate_remove(sd_bus_message *m, void *userdata, sd_bus_error *ret_error)
{
    arm_certificate_entry_s cert = { };
    int ret;

    ret = sd_bus_message_read(m, "s", &cert.cert);
    if (ret < 0)
        return sd_bus_error_set_errno(ret_error, -ret);
    /* See comment in dbus_root_certificate_add() */
    cert.cert_len = strlen((char *)cert.cert) + 1;
    // FIXME: I think that the removed cert is not freed
    ret = arm_network_trusted_certificate_remove(&cert);
    if (ret < 0)
        return sd_bus_error_set_errno(ret_error, EINVAL);

    sd_bus_reply_method_return(m, NULL);
    return 0;
}

static int dbus_revoke_node(sd_bus_message *m, void *userdata, sd_bus_error *ret_error)
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

static int dbus_revoke_apply(sd_bus_message *m, void *userdata, sd_bus_error *ret_error)
{
    struct wsbr_ctxt *ctxt = userdata;
    int ret;

    ret = ws_bbr_node_access_revoke_start(ctxt->rcp_if_id);
    if (ret < 0)
        return sd_bus_error_set_errno(ret_error, EINVAL);
    sd_bus_reply_method_return(m, NULL);
    return 0;
}

int dbus_get_ws_pan_id(sd_bus *bus, const char *path, const char *interface,
                       const char *property, sd_bus_message *reply,
                       void *userdata, sd_bus_error *ret_error)
{
    protocol_interface_info_entry_t *net_if = protocol_stack_interface_info_get_by_id(*(int *)userdata);
    int ret;

    if (!net_if || !net_if->ws_info)
        return sd_bus_error_set_errno(ret_error, EINVAL);
    ret = sd_bus_message_append(reply, "q", net_if->ws_info->network_pan_id);
    WARN_ON(ret < 0, "%s: %s", property, strerror(-ret));
    return 0;
}

int wsbrd_get_ws_domain(sd_bus *bus, const char *path, const char *interface,
                        const char *property, sd_bus_message *reply,
                        void *userdata, sd_bus_error *ret_error)
{
    int *domain = userdata;
    int ret;

    ret = sd_bus_message_append(reply, "s", val_to_str(*domain, valid_ws_domains));
    WARN_ON(ret < 0, "%s", strerror(-ret));
    return 0;
}

int wsbrd_get_ws_size(sd_bus *bus, const char *path, const char *interface,
                        const char *property, sd_bus_message *reply,
                        void *userdata, sd_bus_error *ret_error)
{
    int *size = userdata;
    int ret;

    ret = sd_bus_message_append(reply, "s", val_to_str(*size, valid_ws_size));
    WARN_ON(ret < 0, "%s", strerror(-ret));
    return 0;
}

int dbus_get_int(sd_bus *bus, const char *path, const char *interface,
                 const char *property, sd_bus_message *reply,
                 void *userdata, sd_bus_error *ret_error)
{
    int *val = userdata;
    int ret;

    ret = sd_bus_message_append(reply, "u", (uint32_t)*val);
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
        SD_BUS_METHOD("DebugPing", "s", NULL,
                      dbus_debug_ping, 0),
        SD_BUS_METHOD("AddRootCertificate", "s", NULL,
                      dbus_root_certificate_add, 0),
        SD_BUS_METHOD("RemoveRootCertificate", "s", NULL,
                      dbus_root_certificate_remove, 0),
        SD_BUS_METHOD("RevokeNode", "ay", NULL,
                      dbus_revoke_node, 0),
        SD_BUS_METHOD("RevokeApply", NULL, NULL,
                      dbus_revoke_apply, 0),
        SD_BUS_PROPERTY("Gtks", "aay", dbus_get_gtks,
                        offsetof(struct wsbr_ctxt, rcp_if_id),
                        SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("Gaks", "aay", dbus_get_gaks,
                        offsetof(struct wsbr_ctxt, rcp_if_id),
                        SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("WisunNetworkName", "s", dbus_get_string,
                        offsetof(struct wsbr_ctxt, ws_name),
                        SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("WisunSize", "s", wsbrd_get_ws_size,
                        offsetof(struct wsbr_ctxt, ws_size),
                        SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("WisunDomain", "s", wsbrd_get_ws_domain,
                        offsetof(struct wsbr_ctxt, ws_domain),
                        SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("WisunMode", "u", dbus_get_int,
                        offsetof(struct wsbr_ctxt, ws_mode),
                        SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("WisunClass", "u", dbus_get_int,
                        offsetof(struct wsbr_ctxt, ws_class),
                        SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("WisunPanId", "q", dbus_get_ws_pan_id,
                        offsetof(struct wsbr_ctxt, rcp_if_id),
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
