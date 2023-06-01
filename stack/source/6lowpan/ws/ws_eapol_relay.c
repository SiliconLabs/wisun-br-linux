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

#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include "common/log_legacy.h"
#include "common/ns_list.h"
#include "stack/mac/fhss_config.h"
#include "stack/mac/mac_api.h"
#include "stack/mac/mac_mcps.h"
#include "stack/ns_address.h"

#include "legacy/net_socket.h"
#include "nwk_interface/protocol.h"
#include "common_protocols/ipv6_constants.h"
#include "common_protocols/ip.h"
#include "6lowpan/mac/mac_helper.h"
#include "6lowpan/mac/mpx_api.h"
#include "6lowpan/ws/ws_config.h"
#include "6lowpan/ws/ws_eapol_pdu.h"
#include "6lowpan/ws/ws_eapol_relay_lib.h"

#include "6lowpan/ws/ws_eapol_relay.h"
#include "app_wsbrd/wsbr.h"

#define TRACE_GROUP "wser"

typedef struct eapol_relay {
    struct net_if *interface_ptr;         /**< Interface pointer */
    ns_address_t remote_addr;                               /**< Remote address (border router address) */
    int socket_id;                                          /**< Socket ID for relay */
    ns_list_link_t link;                                    /**< Link */
} eapol_relay_t;

static eapol_relay_t *ws_eapol_relay_get(struct net_if *interface_ptr);
static int8_t ws_eapol_relay_eapol_pdu_address_check(struct net_if *interface_ptr, const uint8_t *eui_64);
static int8_t ws_eapol_relay_eapol_pdu_receive(struct net_if *interface_ptr, const uint8_t *eui_64, const void *pdu, uint16_t size);
#ifdef HAVE_SOCKET_API
static void ws_eapol_relay_socket_cb(void *cb);
#endif

static const eapol_pdu_recv_cb_data_t eapol_pdu_recv_cb_data = {
    .priority = EAPOL_PDU_RECV_LOW_PRIORITY,
    .filter_requsted = true,
    .addr_check = ws_eapol_relay_eapol_pdu_address_check,
    .receive = ws_eapol_relay_eapol_pdu_receive
};

static eapol_relay_t * g_eapol_relay = NULL;

int ws_eapol_relay_get_socket_fd()
{
    struct net_if *interface_ptr = protocol_stack_interface_info_get();
    eapol_relay_t *eapol_relay = ws_eapol_relay_get(interface_ptr);
    if (eapol_relay)
        return eapol_relay->socket_id;
    else
        return -1;
}

int8_t ws_eapol_relay_start(struct net_if *interface_ptr, uint16_t local_port, const uint8_t *remote_addr, uint16_t remote_port)
{
    if (!interface_ptr || !remote_addr) {
        return -1;
    }

    eapol_relay_t *eapol_relay = ws_eapol_relay_get(interface_ptr);

    if (eapol_relay) {
        memcpy(&eapol_relay->remote_addr.address, remote_addr, 16);
        return 0;
    }

    eapol_relay = malloc(sizeof(eapol_relay_t));
    if (!eapol_relay) {
        return -1;
    }

    eapol_relay->interface_ptr = interface_ptr;

    eapol_relay->remote_addr.type = ADDRESS_IPV6;
    memcpy(&eapol_relay->remote_addr.address, remote_addr, 16);
    eapol_relay->remote_addr.identifier = remote_port;

#ifndef HAVE_SOCKET_API
    struct wsbr_ctxt *ctxt = &g_ctxt;
    struct sockaddr_in6 sockaddr = { .sin6_family = AF_INET6, .sin6_addr = IN6ADDR_ANY_INIT, .sin6_port = htons(local_port) };
    eapol_relay->socket_id = socket(AF_INET6, SOCK_DGRAM, 0);
    if (eapol_relay->socket_id < 0)
        FATAL(1, "%s: socket: %m", __func__);
    if (setsockopt(eapol_relay->socket_id, SOL_SOCKET, SO_BINDTODEVICE, ctxt->config.tun_dev, IF_NAMESIZE) < 0)
        FATAL(1, "%s: setsocketopt: %m", __func__);
    if (bind(eapol_relay->socket_id, (struct sockaddr *) &sockaddr, sizeof(sockaddr)) < 0)
        FATAL(1, "%s: bind: %m", __func__);
#else
    eapol_relay->socket_id = socket_open(IPV6_NH_UDP, local_port, &ws_eapol_relay_socket_cb);
    if (eapol_relay->socket_id < 0) {
        free(eapol_relay);
        return -1;
    }
#endif
#ifdef HAVE_SOCKET_API
    int16_t tc = IP_DSCP_CS6 << IP_TCLASS_DSCP_SHIFT;
    socket_setsockopt(eapol_relay->socket_id, SOCKET_IPPROTO_IPV6, SOCKET_IPV6_TCLASS, &tc, sizeof(tc));
#endif

    if (ws_eapol_pdu_cb_register(interface_ptr, &eapol_pdu_recv_cb_data) < 0) {
        free(eapol_relay);
        return -1;
    }

    g_eapol_relay = eapol_relay;

    return 0;
}

int8_t ws_eapol_relay_delete(struct net_if *interface_ptr)
{
    if (!interface_ptr) {
        return -1;
    }

    eapol_relay_t *eapol_relay = ws_eapol_relay_get(interface_ptr);
    if (!eapol_relay) {
        return -1;
    }

#ifndef HAVE_SOCKET_API
    close(eapol_relay->socket_id);
#else
    socket_close(eapol_relay->socket_id);
#endif

    ws_eapol_pdu_cb_unregister(interface_ptr, &eapol_pdu_recv_cb_data);

    g_eapol_relay = NULL;
    free(eapol_relay);

    return 0;
}

static eapol_relay_t *ws_eapol_relay_get(struct net_if *interface_ptr)
{
    return g_eapol_relay;
}

static int8_t ws_eapol_relay_eapol_pdu_address_check(struct net_if *interface_ptr, const uint8_t *eui_64)
{
    (void) eui_64;
    (void) interface_ptr;

    // Low priority, always route all here if asked
    return 0;
}

static int8_t ws_eapol_relay_eapol_pdu_receive(struct net_if *interface_ptr, const uint8_t *eui_64, const void *pdu, uint16_t size)
{
    eapol_relay_t *eapol_relay = ws_eapol_relay_get(interface_ptr);
    if (!eapol_relay) {
        return -1;
    }

    ws_eapol_relay_lib_send_to_relay(eapol_relay->socket_id, eui_64, &eapol_relay->remote_addr, pdu, size);
    return 0;
}

#ifndef HAVE_SOCKET_API
void ws_eapol_relay_socket_cb(int fd)
#else
static void ws_eapol_relay_socket_cb(void *cb)
#endif
{
    uint8_t *socket_pdu = NULL;
    ssize_t data_len;
#ifndef HAVE_SOCKET_API
    uint8_t data[2048];

    data_len = recv(fd, data, sizeof(data), 0);
    if (data_len <= 0)
        return;
#else
    socket_callback_t *cb_data = cb;
    ns_address_t src_addr;

    if (cb_data->event_type != SOCKET_DATA) {
        return;
    }

    data_len = cb_data->d_len;
#endif

    eapol_relay_t *eapol_relay = g_eapol_relay;

    if (!eapol_relay) {
        return;
    }
    socket_pdu = malloc(data_len);
    if (!socket_pdu)
        return;

#ifndef HAVE_SOCKET_API
    memcpy(socket_pdu, data, data_len);
#else
    if (socket_recvfrom(cb_data->socket_id, socket_pdu, cb_data->d_len, 0, &src_addr) != cb_data->d_len) {
        free(socket_pdu);
        return;
    }
#endif

    // EAPOL PDU data length is zero (message contains only supplicant EUI-64 and KMP ID)
    if (data_len == 9) {
        ws_eapol_pdu_mpx_eui64_purge(eapol_relay->interface_ptr, socket_pdu);
        free(socket_pdu);
        return;
    }

    //First 8 byte is EUID64 and rsr payload
    if (data_len < 8 || ws_eapol_pdu_send_to_mpx(eapol_relay->interface_ptr, socket_pdu, socket_pdu + 8, data_len - 8, socket_pdu, NULL, 0) < 0) {
        free(socket_pdu);
    }
}

