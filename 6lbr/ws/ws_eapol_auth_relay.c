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

#include "common/capture.h"
#include "common/endian.h"
#include "common/log_legacy.h"
#include "common/ns_list.h"
#include "common/specs/ipv6.h"

#include "net/protocol.h"
#include "net/ns_address.h"
#include "6lowpan/mac/mac_helper.h"
#include "6lowpan/mac/mpx_api.h"
#include "ws/ws_config.h"
#include "ws/ws_eapol_pdu.h"
#include "ws/ws_eapol_relay_lib.h"

#include "ws/ws_eapol_auth_relay.h"
#include "app/wsbr.h"

#define TRACE_GROUP "wsar"

typedef struct eapol_auth_relay {
    struct net_if *interface_ptr;         /**< Interface pointer */
    ns_address_t remote_addr;                               /**< Remote address and port */
    ns_address_t relay_addr;                                /**< Relay address */
    int socket_id;                                          /**< Socket ID for relay */
    ns_list_link_t link;                                    /**< Link */
} eapol_auth_relay_t;

static eapol_auth_relay_t *ws_eapol_auth_relay_get(struct net_if *interface_ptr);
static int8_t ws_eapol_auth_relay_send_to_kmp(eapol_auth_relay_t *eapol_auth_relay, const uint8_t *eui_64, const uint8_t *ip_addr, uint16_t port, const void *data, uint16_t data_len);

static eapol_auth_relay_t *g_eapol_auth_relay;

int ws_eapol_auth_relay_get_socket_fd()
{
    struct net_if *interface_ptr = protocol_stack_interface_info_get();
    eapol_auth_relay_t *eapol_auth_relay = ws_eapol_auth_relay_get(interface_ptr);
    if (eapol_auth_relay)
        return eapol_auth_relay->socket_id;
    else
        return -1;
}

int8_t ws_eapol_auth_relay_start(struct net_if *interface_ptr, uint16_t local_port, const uint8_t *remote_addr, uint16_t remote_port)
{
    if (!interface_ptr || !remote_addr) {
        return -1;
    }

    if (ws_eapol_auth_relay_get(interface_ptr)) {
        return 0;
    }

    struct wsbr_ctxt *ctxt = &g_ctxt;
    struct sockaddr_in6 sockaddr = { .sin6_family = AF_INET6, .sin6_addr = IN6ADDR_ANY_INIT, .sin6_port = htons(local_port) };
    eapol_auth_relay_t *eapol_auth_relay = malloc(sizeof(eapol_auth_relay_t));
    if (!eapol_auth_relay) {
        return -1;
    }

    eapol_auth_relay->interface_ptr = interface_ptr;

    eapol_auth_relay->remote_addr.type = ADDRESS_IPV6;
    memcpy(&eapol_auth_relay->relay_addr.address, remote_addr, 16);
    eapol_auth_relay->relay_addr.identifier = remote_port;

    eapol_auth_relay->socket_id = socket(AF_INET6, SOCK_DGRAM, 0);
    if (eapol_auth_relay->socket_id < 0)
        FATAL(1, "%s: socket: %m", __func__);
    capture_register_netfd(eapol_auth_relay->socket_id);
    if (setsockopt(eapol_auth_relay->socket_id, SOL_SOCKET, SO_BINDTODEVICE, ctxt->config.tun_dev, IF_NAMESIZE) < 0)
        FATAL(1, "%s: setsocketopt: %m", __func__);
    if (bind(eapol_auth_relay->socket_id, (struct sockaddr *) &sockaddr, sizeof(sockaddr)) < 0)
        FATAL(1, "%s: bind: %m", __func__);
    if (eapol_auth_relay->socket_id < 0) {
        free(eapol_auth_relay);
        return -1;
    }

    g_eapol_auth_relay = eapol_auth_relay;

    return 0;
}

static eapol_auth_relay_t *ws_eapol_auth_relay_get(struct net_if *interface_ptr)
{
    return g_eapol_auth_relay;
}

void ws_eapol_auth_relay_socket_cb(int fd)
{
    ssize_t socket_data_len;
    uint8_t data[2048];
    uint8_t *socket_pdu = NULL;
    uint16_t data_len;
    ns_address_t src_addr;
    struct sockaddr_in6 sockaddr;
    socklen_t sockaddr_len = sizeof(struct sockaddr_in6);
    eapol_auth_relay_t *eapol_auth_relay = g_eapol_auth_relay;

    if (!eapol_auth_relay) {
        return;
    }

    socket_data_len = xrecvfrom(fd, data, sizeof(data), 0, (struct sockaddr *) &sockaddr, &sockaddr_len);
    if (socket_data_len <= 0)
        return;

    socket_pdu = malloc(socket_data_len);
    if (!socket_pdu)
        return;

    memcpy(socket_pdu, data, socket_data_len);

    src_addr.type = ADDRESS_IPV6;
    src_addr.identifier = ntohs(sockaddr.sin6_port);
    memcpy(src_addr.address, &sockaddr.sin6_addr, 16);

    // Message from source port 10254 (KMP service) -> to IP relay on node or on authenticator
    if (src_addr.identifier == eapol_auth_relay->relay_addr.identifier) {
        uint8_t *ptr = socket_pdu;
        uint8_t *eui_64;
        ns_address_t relay_ip_addr;
        relay_ip_addr.type = ADDRESS_IPV6;
        memcpy(relay_ip_addr.address, ptr, 16);
        ptr += 16;
        relay_ip_addr.identifier = read_be16(ptr);
        ptr += 2;
        eui_64 = ptr;
        ptr += 8;
        data_len = socket_data_len - 26;
        /* If EAPOL PDU data length is zero (message contains only supplicant EUI-64 and KMP ID)
         * i.e. is purge message and is not going to authenticator local relay then ignores message
         */
        if (data_len == 1 && !addr_ipv6_equal(relay_ip_addr.address, eapol_auth_relay->relay_addr.address)) {
            free(socket_pdu);
            return;
        }
        ws_eapol_relay_lib_send_to_relay(eapol_auth_relay->socket_id, eui_64, &relay_ip_addr,
                                         ptr, data_len);
        free(socket_pdu);
        // Other source port (either 10253 or node relay source port) -> to KMP service
    } else {
        uint8_t *ptr = socket_pdu;
        ws_eapol_auth_relay_send_to_kmp(eapol_auth_relay, ptr, src_addr.address, src_addr.identifier,
                                        ptr + 8, socket_data_len - 8);
        free(socket_pdu);
    }
}

static int8_t ws_eapol_auth_relay_send_to_kmp(eapol_auth_relay_t *eapol_auth_relay, const uint8_t *eui_64, const uint8_t *ip_addr, uint16_t port, const void *data, uint16_t data_len)
{
    struct sockaddr_in6 sockaddr = { .sin6_family = AF_INET6, .sin6_port = htons(eapol_auth_relay->relay_addr.identifier) };
    memcpy(&sockaddr.sin6_addr, eapol_auth_relay->relay_addr.address , 16);

    uint8_t temp_array[26];
    struct iovec msg_iov[2];
    struct msghdr msghdr = { };
    //Set messages name buffer
    msghdr.msg_name = &sockaddr;
    msghdr.msg_namelen = sizeof(struct sockaddr_in6);
    msghdr.msg_iov = &msg_iov[0];
    msghdr.msg_iovlen = 2;
    msghdr.msg_control = NULL;
    msghdr.msg_controllen = 0;
    uint8_t *ptr = temp_array;
    memcpy(ptr, ip_addr, 16);
    ptr += 16;
    ptr = write_be16(ptr, port);
    memcpy(ptr, eui_64, 8);
    msg_iov[0].iov_base = temp_array;
    msg_iov[0].iov_len = 26;
    msg_iov[1].iov_base = (void *)data;
    msg_iov[1].iov_len = data_len;
    if (xsendmsg(eapol_auth_relay->socket_id, &msghdr, 0) <= 0)
        tr_debug("ws_eapol_auth_relay_send_to_kmp: %m");
    return 0;
}
