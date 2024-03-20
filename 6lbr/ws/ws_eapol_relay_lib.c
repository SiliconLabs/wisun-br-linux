/*
 * Copyright (c) 2018-2019, Pelion and affiliates.
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
#include <sys/socket.h>
#include <netinet/in.h>

#include "common/capture.h"
#include "common/log_legacy.h"
#include "common/ns_list.h"

#include "net/ns_address.h"
#include "ws/ws_config.h"
#include "ws/ws_eapol_relay_lib.h"

#define TRACE_GROUP "wsrl"

int8_t ws_eapol_relay_lib_send_to_relay(int socket_id,
                                        const uint8_t *eui_64,
                                        const ns_address_t *dest_addr,
                                        const void *data,
                                        uint16_t data_len)
{
    struct sockaddr_in6 sockaddr = { .sin6_family = AF_INET6, .sin6_port = htons(dest_addr->identifier) };
    struct msghdr msghdr = { };
    struct iovec msg_iov[2];

    memcpy(&sockaddr.sin6_addr, dest_addr->address, 16);
    msghdr.msg_name = &sockaddr;
    msghdr.msg_namelen = sizeof(struct sockaddr_in6);
    msghdr.msg_iov = &msg_iov[0];
    msghdr.msg_iovlen = 2;
    msghdr.msg_control = NULL;
    msghdr.msg_controllen = 0;
    msg_iov[0].iov_base = (void *)eui_64;
    msg_iov[0].iov_len = 8;
    msg_iov[1].iov_base = (void *)data;
    msg_iov[1].iov_len = data_len;
    if (xsendmsg(socket_id, &msghdr, 0) <= 0)
        tr_debug("ws_eapol_relay_lib_send_to_relay: %m");
    return 0;
}


