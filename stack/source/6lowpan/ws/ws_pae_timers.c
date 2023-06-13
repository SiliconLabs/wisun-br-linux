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
#include "stack/mac/fhss_config.h"
#include "stack/ws_management_api.h"

#include "nwk_interface/protocol.h"
#include "security/protocols/sec_prot_cfg.h"
#include "6lowpan/ws/ws_config.h"
#include "6lowpan/ws/ws_cfg_settings.h"

#include "6lowpan/ws/ws_pae_timers.h"

#define TRACE_GROUP "wspt"

#define SECONDS_IN_MINUTE                       60

#define DEFAULT_GTK_REQUEST_IMIN                4                       // 4 minutes
#define DEFAULT_GTK_REQUEST_IMAX                64                      // 64 minutes

static void ws_pae_timers_calculate(sec_timer_gtk_cfg_t *timer_settings);

void ws_pae_timers_settings_init(sec_timer_cfg_t *timer_settings, ws_sec_timer_cfg_t *new_timer_settings)
{
    if (timer_settings == NULL || new_timer_settings == NULL) {
        return;
    }

    timer_settings->pmk_lifetime = new_timer_settings->pmk_lifetime * SECONDS_IN_MINUTE;
    timer_settings->ptk_lifetime = new_timer_settings->ptk_lifetime * SECONDS_IN_MINUTE;
    timer_settings->gtk.expire_offset = new_timer_settings->gtk_expire_offset * SECONDS_IN_MINUTE;
    timer_settings->gtk.new_act_time = new_timer_settings->gtk_new_act_time;
    timer_settings->gtk.new_install_req = new_timer_settings->gtk_new_install_req;
    timer_settings->gtk.revocat_lifetime_reduct = new_timer_settings->ffn_revocat_lifetime_reduct;
    timer_settings->lgtk.expire_offset = new_timer_settings->lgtk_expire_offset * SECONDS_IN_MINUTE;
    timer_settings->lgtk.new_act_time = new_timer_settings->lgtk_new_act_time;
    timer_settings->lgtk.new_install_req = new_timer_settings->lgtk_new_install_req;
    timer_settings->lgtk.revocat_lifetime_reduct = new_timer_settings->lfn_revocat_lifetime_reduct;
#ifdef HAVE_PAE_SUPP
    timer_settings->gtk.request_imin = new_timer_settings->gtk_request_imin * SECONDS_IN_MINUTE;
    timer_settings->gtk.request_imax = new_timer_settings->gtk_request_imax * SECONDS_IN_MINUTE;
    timer_settings->gtk.max_mismatch = new_timer_settings->gtk_max_mismatch * SECONDS_IN_MINUTE;
    timer_settings->lgtk.request_imin = 0;
    timer_settings->lgtk.request_imax = 0;
    timer_settings->lgtk.max_mismatch = new_timer_settings->lgtk_max_mismatch * SECONDS_IN_MINUTE;
#endif

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

#ifdef HAVE_PAE_SUPP
    // If time to update results smaller GTK request Imax use it for calculation otherwise use GTK max mismatch
    if (time_to_gtk_update < timer_gtk_settings->max_mismatch) {
        // If time to update is smaller than GTK request Imax update GTK request values
        if (timer_gtk_settings->request_imax > time_to_gtk_update) {
            timer_gtk_settings->request_imin = time_to_gtk_update / 4;
            timer_gtk_settings->request_imax = time_to_gtk_update / 2;
            tr_info("GTK request timers adjusted Imin: %i, Imax: %i", timer_gtk_settings->request_imin, timer_gtk_settings->request_imax);
        }
    } else if (timer_gtk_settings->request_imax > timer_gtk_settings->max_mismatch) {
        // If GTK request Imax is larger than GTK max mismatch update GTK request values

        // For small GTK max mismatch times, scale the Imin to be larger than default  4 / 64;
        uint16_t scaler;
        if (timer_gtk_settings->max_mismatch < 50) {
            scaler = 10;
        } else if (timer_gtk_settings->max_mismatch > 600) {
            scaler = 1;
        } else {
            // About 1 minute mismatch, results 37 seconds Imin and 60 seconds Imax
            scaler = (600 - timer_gtk_settings->max_mismatch) / 54;
        }

        timer_gtk_settings->request_imin = timer_gtk_settings->max_mismatch * scaler * DEFAULT_GTK_REQUEST_IMIN / DEFAULT_GTK_REQUEST_IMAX;
        timer_gtk_settings->request_imax = timer_gtk_settings->max_mismatch;
        tr_info("GTK request timers adjusted Imin: %i, Imax: %i", timer_gtk_settings->request_imin, timer_gtk_settings->request_imax);
    }
#endif
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

