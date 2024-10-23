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

#ifndef KMP_SOCKET_IF_H_
#define KMP_SOCKET_IF_H_
#include <stdint.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <stdbool.h>

typedef struct kmp_service kmp_service_t;

/*
 * Authenticator KMP socket interface to/from EAPOL authenticator relay. EAPOL
 * authenticator relay address and port are provided in register call (remote
 * address and remote port parameters)
 *
 * Authenticator KMP socket must be bound to port that EAPOL authenticator
 * uses to send messages to Authenticator KMP. Default port is 10254 (local port
 * parameter)
 *
 */

int kmp_socket_if_get_pae_socket_fd();
void kmp_socket_if_pae_socket_cb(int fd);

/**
 * kmp_socket_if_register register socket interface to KMP service
 *
 * \param service KMP service to register to
 * \param instance_id instance identifier, for new instance set to zero when called
 * \param relay interface is relay interface
 * \param local_port local port
 * \param remote_addr remote address
 * \param remote_port remote port
 *
 * \return < 0 failure
 * \return >= 0 success
 *
 */
int8_t kmp_socket_if_register(kmp_service_t *service, uint8_t *instance_id, bool relay, uint16_t local_port, const void *remote_addr, uint16_t remote_port);

/**
 * kmp_socket_if_register_radius register native socket interface to KMP service
 *
 * \param service KMP service to register to
 * \param instance_id instance identifier, for new instance set to zero when called
 * \param relay interface is relay interface
 * \param local_port local port
 * \param remote_addr remote native socket address
 * \param remote_port remote port
 *
 * \return < 0 failure
 * \return >= 0 success
 *
 */

int kmp_socket_if_get_radius_sockfd();
uint8_t kmp_socket_if_radius_socket_cb(int fd);


#endif
