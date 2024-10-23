/*
 * Copyright (c) 2019, Pelion and affiliates.
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

#ifndef TLS_SEC_PROT_H_
#define TLS_SEC_PROT_H_
#include <stdint.h>

struct kmp_service;

/*
 * TLS security protocol
 *
 */

/* TLS send buffer size not including certificates. This should include e.g. on
 * server: server hello, server key exchange, certificate request and server
 * hello done. */
#define TLS_SEC_PROT_SEND_BUFFER_SIZE             500

/* TLS send buffer size increment if it is detected that buffer is too small */
#define TLS_SEC_PROT_SEND_BUFFER_SIZE_INCREMENT   1000

void server_tls_sec_prot_register(struct kmp_service *service);

#endif
