/*
 * Copyright (c) 2020, Pelion and affiliates.
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

#ifndef RADIUS_EAP_TLS_SEC_PROT_H_
#define RADIUS_EAP_TLS_SEC_PROT_H_
#include <stdint.h>

struct kmp_service;

/*
 * Authenticator RADIUS EAP-TLS security protocol. Specified in RFC 5216.
 *
 */

void radius_eap_tls_sec_prot_register(struct kmp_service *service);

#endif
