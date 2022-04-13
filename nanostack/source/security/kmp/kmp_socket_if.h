/*
 * Copyright (c) 2016-2020, Pelion and affiliates.
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

#include <sys/socket.h>

typedef struct kmp_service_s kmp_service_t;

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
int8_t kmp_socket_if_register(kmp_service_t *service, uint8_t *instance_id, bool relay, uint16_t local_port, const uint8_t *remote_addr, uint16_t remote_port);

/**
 * kmp_socket_if_unregister unregister socket interface from KMP service
 *
 * \param service KMP service to unregister from
 *
 * \return < 0 failure
 * \return >= 0 success
 *
 */
int8_t kmp_socket_if_unregister(kmp_service_t *service);

/**
 * kmp_socket_if_register_native register native socket interface to KMP service
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
int8_t kmp_socket_if_register_native(kmp_service_t *service, uint8_t *instance_id, bool relay, uint16_t local_port, const struct sockaddr_storage *remote_addr, uint16_t remote_port);

/**
 * kmp_socket_if_get_native_sockfd return the first native socket found in KMP service
 *
 * \return < 0 failure
 * \return >= 0 success
 *
 */
int kmp_socket_if_get_native_sockfd();

/**
 * kmp_socket_if_data_from_ext_radius transfer data from wsbrd to KMP
 *
 * \return < 0 failure (data not sent)
 * \return >= 0 success the number of bytes transferred
 *
 */
uint8_t kmp_socket_if_data_from_ext_radius();


#endif /* KMP_SOCKET_IF_H_ */
