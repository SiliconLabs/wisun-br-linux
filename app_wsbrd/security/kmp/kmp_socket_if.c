/*
 * Copyright (c) 2016-2020, Pelion and affiliates.
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
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>

#include "common/capture.h"
#include "common/endian.h"
#include "common/log_legacy.h"
#include "common/ns_list.h"

#include "net/protocol.h"
#include "common/specs/ipv6.h"
#include "net/ns_address.h"
#include "ws/ws_config.h"
#include "security/protocols/sec_prot_cfg.h"
#include "security/kmp/kmp_addr.h"
#include "security/kmp/kmp_api.h"

#include "security/kmp/kmp_socket_if.h"
#include "app/wsbrd.h"


#define TRACE_GROUP "kmsi"

#define SOCKET_IF_HEADER_SIZE       27
#define KMP_INSTANCE_NUMBER         2
#define KMP_RELAY_INSTANCE_INDEX    0
#define KMP_RADIUS_INSTANCE_INDEX   1

typedef struct kmp_socket_if {
    kmp_service_t *kmp_service;                       /**< KMP service */
    uint8_t instance_id;                              /**< Instance identifier */
    bool relay;                                       /**< Interface is relay interface */
    ns_address_t remote_addr;                         /**< Remote address */
    int kmp_socket_id;                                /**< Socket ID */
    ns_list_link_t link;                              /**< Link */
    struct sockaddr_storage remote_sockaddr;          /**< Remote socket address (can be INET4 or INET6) */
} kmp_socket_if_t;

static int8_t kmp_socket_if_send(kmp_service_t *service, uint8_t instance_id, kmp_type_e kmp_id, const kmp_addr_t *addr, void *pdu, uint16_t size, uint8_t tx_identifier, uint8_t connection_num);

static kmp_socket_if_t *g_kmp_socket_if_instances[KMP_INSTANCE_NUMBER];

int8_t kmp_socket_if_register(kmp_service_t *service, uint8_t *instance_id, bool relay, uint16_t local_port, const void *remote_addr,  uint16_t remote_port)
{
    if (!service || !remote_addr) {
        return -1;
    }

    kmp_socket_if_t *socket_if = NULL;
    bool new_socket_if_allocated = false;
    struct wsbr_ctxt *ctxt = &g_ctxt;
    struct sockaddr_in6 sockaddr = { .sin6_family = AF_INET6, .sin6_addr = IN6ADDR_ANY_INIT, .sin6_port = htons(local_port) };
    struct sockaddr_storage radius_cli_bind = { };
    int kmp_socket_if_instance_index = relay ? KMP_RELAY_INSTANCE_INDEX : KMP_RADIUS_INSTANCE_INDEX;

    if (g_kmp_socket_if_instances[kmp_socket_if_instance_index] != NULL) {
        if (g_kmp_socket_if_instances[kmp_socket_if_instance_index]->kmp_service == service &&
            g_kmp_socket_if_instances[kmp_socket_if_instance_index]->instance_id == *instance_id)
            socket_if = g_kmp_socket_if_instances[kmp_socket_if_instance_index];
    }

    if (!socket_if) {
        socket_if = malloc(sizeof(kmp_socket_if_t));
        if (!socket_if) {
            return -1;
        }
        memset(socket_if, 0, sizeof(kmp_socket_if_t));
        socket_if->kmp_socket_id = -1;
        new_socket_if_allocated = true;
    }

    socket_if->kmp_service = service;

    if (*instance_id == 0) {
        socket_if->instance_id = kmp_socket_if_instance_index + 1;
        *instance_id = socket_if->instance_id;
    }

    socket_if->relay = relay;

    socket_if->remote_addr.type = ADDRESS_IPV6;

    if (relay) {
        bool address_changed = false;
        if (memcmp(&socket_if->remote_addr.address, remote_addr, 16) != 0 ||
            socket_if->remote_addr.identifier != remote_port) {
            address_changed = true;
        }
        memcpy(&socket_if->remote_addr.address, remote_addr, 16);
        socket_if->remote_addr.identifier = remote_port;

        if ((socket_if->kmp_socket_id < 1) || address_changed) {
            if (socket_if->kmp_socket_id >= 0) {
                close(socket_if->kmp_socket_id);
            }
            socket_if->kmp_socket_id = socket(AF_INET6, SOCK_DGRAM, 0);
            if (socket_if->kmp_socket_id < 0)
                FATAL(1, "%s: socket: %m", __func__);
            capture_register_netfd(socket_if->kmp_socket_id);
            if (setsockopt(socket_if->kmp_socket_id, SOL_SOCKET, SO_BINDTODEVICE, ctxt->tun.ifname, IF_NAMESIZE) < 0)
                FATAL(1, "%s: setsocketopt: %m", __func__);
            if (bind(socket_if->kmp_socket_id, (struct sockaddr *) &sockaddr, sizeof(sockaddr)) < 0)
                FATAL(1, "%s: bind: %m", __func__);
        }
    } else {
        if ((socket_if->kmp_socket_id < 1)) {

            if (socket_if->kmp_socket_id >= 0)
                close(socket_if->kmp_socket_id);

            memcpy(&socket_if->remote_sockaddr, remote_addr, sizeof(struct sockaddr_storage));
            ((struct sockaddr_in *) &socket_if->remote_sockaddr)->sin_port = htons(remote_port);
            socket_if->kmp_socket_id = socket(socket_if->remote_sockaddr.ss_family, SOCK_DGRAM, 0);
            if (socket_if->kmp_socket_id < 0)
                FATAL(1, "%s: socket: %m", __func__);
            capture_register_netfd(socket_if->kmp_socket_id);
            radius_cli_bind.ss_family = ((struct sockaddr_storage *) remote_addr)->ss_family;
            if (bind(socket_if->kmp_socket_id, (struct sockaddr *)&radius_cli_bind, sizeof(radius_cli_bind)) < 0)
                FATAL(1, "%s: bind: %m", __func__);
        }
    }



    uint8_t header_size = 0;
    if (relay) {
        header_size = SOCKET_IF_HEADER_SIZE;
    }

    if (kmp_service_msg_if_register(service, *instance_id, kmp_socket_if_send, header_size) < 0) {
        if (socket_if->kmp_socket_id >= 0)
            close(socket_if->kmp_socket_id);
        free(socket_if);
        return -1;
    }

    if (new_socket_if_allocated) {
        g_kmp_socket_if_instances[kmp_socket_if_instance_index] = socket_if;
    }

    return 0;
}

static int8_t kmp_socket_if_send(kmp_service_t *service, uint8_t instance_id, kmp_type_e kmp_id, const kmp_addr_t *addr, void *pdu, uint16_t size, uint8_t tx_identifier, uint8_t connection_num)
{
    (void) tx_identifier;
    (void) connection_num;

    if (!service || !pdu || !addr) {
        return -1;
    }

    if (connection_num >= 1) {
        return -1;
    }

    ssize_t ret;
    kmp_socket_if_t *socket_if = g_kmp_socket_if_instances[--instance_id];
    struct sockaddr_in6 sockaddr = { .sin6_family = AF_INET6, .sin6_port = htons(socket_if->remote_addr.identifier) };
    memcpy(&sockaddr.sin6_addr, socket_if->remote_addr.address, 16);

    if (!socket_if) {
        return -1;
    }

    if (socket_if->relay) {
        //Build UPD Relay
        uint8_t *ptr = pdu;
        memcpy(ptr, addr->relay_address, 16);
        ptr += 16;
        ptr = write_be16(ptr, addr->port);
        memcpy(ptr, kmp_address_eui_64_get(addr), 8);
        ptr += 8;
        *ptr = kmp_id;
    }

    if (instance_id == KMP_RELAY_INSTANCE_INDEX)
        ret = xsendto(socket_if->kmp_socket_id, pdu, size, 0,
                      (struct sockaddr *)&sockaddr, sizeof(struct sockaddr_in6));
    else if (instance_id == KMP_RADIUS_INSTANCE_INDEX)
        ret = xsendto(socket_if->kmp_socket_id, pdu, size, 0,
                      (struct sockaddr *)&socket_if->remote_sockaddr, sizeof(socket_if->remote_sockaddr));
    else
        ret = -1;

    if (ret < 0 || ret != size) {
        tr_error("kmp_socket_if_send, instance_id = %d sendto: %m", instance_id);
        return -1;
    }

    return 0;
}

int kmp_socket_if_get_pae_socket_fd()
{
    if (g_kmp_socket_if_instances[KMP_RELAY_INSTANCE_INDEX])
        return g_kmp_socket_if_instances[KMP_RELAY_INSTANCE_INDEX]->kmp_socket_id;

    return -1;
}

void kmp_socket_if_pae_socket_cb(int fd)
{
    kmp_socket_if_t *socket_if = g_kmp_socket_if_instances[KMP_RELAY_INSTANCE_INDEX];
    uint8_t connection_num = 0;
    ssize_t data_len;
    uint8_t data[2048];
    uint8_t *pdu = NULL;

    data_len = xrecv(fd, data, sizeof(data), 0);
    if (data_len <= 0)
        return;

    if (!socket_if) {
        return;
    }

    pdu = malloc(data_len);
    if (!pdu)
        return;

    memcpy(pdu, data, data_len);

    kmp_addr_t addr;
    memset(&addr, 0, sizeof(kmp_addr_t));
    kmp_type_e type = KMP_TYPE_NONE;
    uint8_t *data_ptr = pdu;

    if (socket_if->relay) {
        addr.type = KMP_ADDR_EUI_64_AND_IP;
        memcpy(addr.relay_address, data_ptr, 16);
        data_ptr += 16;
        addr.port = read_be16(data_ptr);
        data_ptr += 2;
        memcpy(addr.eui_64, data_ptr, 8);
        data_ptr += 8;

        type = kmp_api_type_from_id_get(*data_ptr++);
        if (type == KMP_TYPE_NONE) {
            free(pdu);
            return;
        }
        data_len -= SOCKET_IF_HEADER_SIZE;
    }

    kmp_service_msg_if_receive(socket_if->kmp_service, socket_if->instance_id, type, &addr, data_ptr, data_len, connection_num);
    free(pdu);
}

int kmp_socket_if_get_radius_sockfd()
{
    if (g_kmp_socket_if_instances[KMP_RADIUS_INSTANCE_INDEX])
        return g_kmp_socket_if_instances[KMP_RADIUS_INSTANCE_INDEX]->kmp_socket_id;

    return -1;
}

uint8_t kmp_socket_if_radius_socket_cb(int fd)
{
    ssize_t size;
    uint8_t radius_recv_buf[4096];
    kmp_socket_if_t *socket_if = g_kmp_socket_if_instances[KMP_RADIUS_INSTANCE_INDEX];
    uint8_t connection_num = 0;
    kmp_addr_t addr = { };
    kmp_type_e type = KMP_TYPE_NONE;

    if (!socket_if) {
        return -1;
    }

    size = xrecv(fd, radius_recv_buf, sizeof(radius_recv_buf), 0);
    if (size < 0)
        return -1;

    kmp_service_msg_if_receive(socket_if->kmp_service, socket_if->instance_id, type, &addr, radius_recv_buf, size, connection_num);

    return size;
}
