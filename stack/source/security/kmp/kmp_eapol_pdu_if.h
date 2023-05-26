/*
 * Copyright (c) 2016-2019, Pelion and affiliates.
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

#ifndef KMP_EAPOL_PDU_IF_H_
#define KMP_EAPOL_PDU_IF_H_
#include <stdint.h>

struct net_if;
struct kmp_service;

/*
 * Supplicant KMP interface to/from EAPOL PDU interface (to MPX).
 */

/**
 * kmp_eapol_pdu_if_register register EAPOL PDU interface to KMP service
 *
 * \param service KMP service to register to
 * \param interface_ptr interface
 *
 * \return < 0 failure
 * \return >= 0 success
 *
 */
int8_t kmp_eapol_pdu_if_register(struct kmp_service *service, struct net_if *interface_ptr);

#endif
