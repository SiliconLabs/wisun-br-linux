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
#include <inttypes.h>
#include "common/log_legacy.h"
#include "common/ns_list.h"

#include "nwk_interface/protocol.h"
#include "security/protocols/sec_prot_cfg.h"
#include "6lowpan/ws/ws_config.h"

#include "6lowpan/ws/ws_pae_timers.h"

#define TRACE_GROUP "wspt"

#define SECONDS_IN_MINUTE                       60

#define DEFAULT_GTK_REQUEST_IMIN                4                       // 4 minutes
#define DEFAULT_GTK_REQUEST_IMAX                64                      // 64 minutes

static void ws_pae_timers_calculate(sec_timer_gtk_cfg_t *timer_settings);

void ws_pae_timers_settings_init(sec_timer_cfg_t *timer_settings, const struct sec_timer_cfg *new_timer_settings)
{
    if (timer_settings == NULL || new_timer_settings == NULL) {
        return;
    }

    *timer_settings = *new_timer_settings;

    ws_pae_timers_calculate(&timer_settings->gtk);
    ws_pae_timers_calculate(&timer_settings->lgtk);
}

static void ws_pae_timers_calculate(struct sec_timer_gtk_cfg *timer_gtk_settings)
{
    uint32_t gtk_revocation_lifetime = timer_gtk_settings->expire_offset / timer_gtk_settings->revocat_lifetime_reduct;
    uint32_t new_gtk_activation_time = timer_gtk_settings->expire_offset / timer_gtk_settings->new_act_time;

    uint32_t time_to_gtk_update = gtk_revocation_lifetime;
    if (gtk_revocation_lifetime > new_gtk_activation_time) {
        time_to_gtk_update = gtk_revocation_lifetime - new_gtk_activation_time;
    }
    tr_info("(L)GTK timers revocation lifetime: %"PRIu32", new activation time: %"PRIu32", time to update: %"PRIu32"",
            gtk_revocation_lifetime, new_gtk_activation_time, time_to_gtk_update);
}

bool ws_pae_timers_gtk_new_install_required(struct sec_timer_gtk_cfg *timer_gtk_cfg, uint32_t seconds)
{
    uint32_t gtk_new_install_req_seconds = timer_gtk_cfg->expire_offset - timer_gtk_cfg->new_install_req * timer_gtk_cfg->expire_offset / 100;

    return timer_gtk_cfg->new_install_req > 0 && seconds < gtk_new_install_req_seconds;
}

bool ws_pae_timers_gtk_new_activation_time(struct sec_timer_gtk_cfg *timer_gtk_cfg, uint32_t seconds)
{
    uint32_t gtk_gtk_new_activation_time_seconds = timer_gtk_cfg->expire_offset / timer_gtk_cfg->new_act_time;

    if (seconds < gtk_gtk_new_activation_time_seconds) {
        return true;
    } else {
        return false;
    }
}

uint32_t ws_pae_timers_gtk_revocation_lifetime_get(struct sec_timer_gtk_cfg *timer_gtk_cfg)
{
    return timer_gtk_cfg->expire_offset / timer_gtk_cfg->revocat_lifetime_reduct;
}
