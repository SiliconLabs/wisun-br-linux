/*
 * Copyright (c) 2020-2021, Pelion and affiliates.
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

#ifndef SEC_PROT_CFG_H_
#define SEC_PROT_CFG_H_
#include <stdint.h>
#include <stdbool.h>
#include <sys/socket.h>
#include "common/trickle_legacy.h"

/* Security protocol configuration settings */

typedef struct sec_prot_cfg {
    trickle_legacy_params_t sec_prot_trickle_params;
    uint16_t sec_prot_retry_timeout;
} sec_prot_cfg_t;

/* Security timer configuration settings */

struct sec_timing {
    uint32_t pmk_lifetime_s;
    uint32_t ptk_lifetime_s;
    uint32_t expire_offset;                     /* GTK lifetime; LGTK_EXPIRE_OFFSET (seconds) */
    uint16_t new_act_time;                      /* GTK_NEW_ACTIVATION_TIME (1/X of expire offset) */
    uint8_t  new_install_req;                   /* GTK_NEW_INSTALL_REQUIRED (percent of LGTK lifetime) */
    uint16_t revocat_lifetime_reduct;           /* REVOCATION_LIFETIME_REDUCTION (reduction of lifetime) */
};

/* Security radius configuration settings */

typedef struct sec_radius_cfg {
    struct sockaddr_storage radius_addr;             /**< Radius server IP address */
    const uint8_t *radius_shared_secret;             /**< Radius shared secret */
    uint16_t radius_shared_secret_len;               /**< Radius shared secret length */
    trickle_legacy_params_t radius_retry_trickle_params; /**< Radius retry trickle params */
    bool radius_addr_set : 1;                        /**< Radius server address is set */
} sec_radius_cfg_t;

typedef struct sec_cfg {
    sec_prot_cfg_t prot_cfg;
    struct sec_timing timing_ffn;
    struct sec_timing timing_lfn;
    sec_radius_cfg_t *radius_cfg;
} sec_cfg_t;

#endif
