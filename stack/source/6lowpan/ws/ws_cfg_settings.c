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

#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include "common/bits.h"
#include "common/ws_regdb.h"
#include "common/log_legacy.h"
#include "common/ns_list.h"
#include "common/events_scheduler.h"
#include "common/specs/ws.h"

#include "nwk_interface/protocol.h"
#include "app_wsbrd/wsbr_cfg.h"
#include "mpl/mpl.h"
#include "6lowpan/ws/ws_common.h"
#include "6lowpan/ws/ws_bbr_api.h"
#include "6lowpan/ws/ws_management_api.h"
#include "6lowpan/ws/ws_bootstrap.h"
#include "6lowpan/ws/ws_pae_controller.h"

#include "6lowpan/ws/ws_cfg_settings.h"

#define TRACE_GROUP "cstr"

#define CFG_SETTINGS_OK                       0
#define CFG_SETTINGS_CHANGED                  1

#define CFG_FLAGS_BOOTSTRAP_SET_VALUES        0x01

#define TRICKLE_IMIN_60_SECS 60
#define TRICKLE_IMIN_30_SECS 30
#define TRICKLE_IMIN_15_SECS 15

typedef struct ws_cfg_nw_size {
    ws_timing_cfg_t timing;             /**< Timing configuration */
    ws_sec_prot_cfg_t sec_prot;         /**< Security protocols configuration */
    ws_mpl_cfg_t mpl;                   /**< Multicast timing configuration*/
} ws_cfg_nw_size_t;

typedef int8_t (*ws_cfg_default_set)(void *cfg);
typedef int8_t (*ws_cfg_validate)(void *new_cfg);
typedef int8_t (*ws_cfg_set)(struct net_if *cur, void *new_cfg, uint8_t flags);

typedef struct ws_cfg_cb {
    ws_cfg_default_set default_set;
    ws_cfg_validate validate;
    ws_cfg_set set;
    uint16_t setting_offset;
} ws_cfg_cb_t;

typedef union {
    ws_timing_cfg_t timing;
    ws_mpl_cfg_t mpl;
    ws_sec_prot_cfg_t sec_prot;
} ws_cfgs_t;


typedef struct cfg_devices_in_config {
    uint8_t max_for_small;
    uint8_t max_for_medium;
    uint8_t max_for_large;
    uint8_t max_for_xlarge;
} cfg_devices_in_config_t;

/* Table for amount of devices that certain configuration should be used
 *
 * larger data rates allow more devices to be used with faster settings.
 *
 * For example with network the size of 2000 devices we use
 * Xlrage configuration with 50kbs data rate.
 * Large configuration with 300kbs data rate.
 * and with 600kbs data rate it is possible to use medium network settings.
 *
 */
const cfg_devices_in_config_t devices_by_datarate[] = {
    { 1,  5, 10,  25}, // Configuration for 50 -100kbs
    { 1, 10, 20,  40}, // Configuration for 150kbs - 200kbs
    { 1, 15, 30,  60}, // Configuration for 300kbs
    { 2, 20, 50, 100}, // Configuration for 600kbs - 2400kbs
};

static void ws_cfg_network_size_config_set_small(ws_cfg_nw_size_t *cfg);
static void ws_cfg_network_size_config_set_medium(ws_cfg_nw_size_t *cfg);
static void ws_cfg_network_size_config_set_large(ws_cfg_nw_size_t *cfg);
static void ws_cfg_network_size_config_set_xlarge(ws_cfg_nw_size_t *cfg);
static void ws_cfg_network_size_config_set_certificate(ws_cfg_nw_size_t *cfg);
static int8_t ws_cfg_mpl_default_set(ws_mpl_cfg_t *cfg);
static int8_t ws_cfg_sec_prot_default_set(ws_sec_prot_cfg_t *cfg);

#define CFG_CB(default_cb, validate_cb, set_cb, offset) \
    {                                                   \
    .default_set = (ws_cfg_default_set) default_cb,     \
    .validate = (ws_cfg_validate) validate_cb,          \
    .set = (ws_cfg_set) set_cb,                         \
    .setting_offset = offset,                           \
    }

// Create validate and set callback table
static const ws_cfg_cb_t cfg_cb[] = {
    // Network size configuration must be done first
    CFG_CB(ws_cfg_timing_default_set, ws_cfg_timing_validate, ws_cfg_timing_set, offsetof(ws_cfg_t, timing)),
    CFG_CB(ws_cfg_mpl_default_set, ws_cfg_mpl_validate, ws_cfg_mpl_set, offsetof(ws_cfg_t, mpl)),
    CFG_CB(ws_cfg_sec_prot_default_set, ws_cfg_sec_prot_validate, ws_cfg_sec_prot_set, offsetof(ws_cfg_t, sec_prot)),
};

#define CFG_CB_NUM (sizeof(cfg_cb) / sizeof(ws_cfg_cb_t))

// Wisun configuration storage
ws_cfg_t ws_cfg;

typedef void (*ws_cfg_network_size_config_set_size)(ws_cfg_nw_size_t *cfg);

static uint8_t ws_cfg_config_get_by_size(struct net_if *cur, uint8_t network_size)
{
    (void)cur;
    uint32_t data_rate = ws_common_datarate_get_from_phy_mode(cur->ws_info.hopping_schedule.phy_mode_id,
                                                              cur->ws_info.hopping_schedule.operating_mode);

    uint8_t index;
    if (data_rate < 150000) {
        index = 0;
    } else if (data_rate < 300000) {
        index = 1;
    } else if (data_rate < 600000) {
        index = 2;
    } else {
        index = 3;
    }

    if (network_size == WS_NETWORK_SIZE_CERTIFICATION) {
        return CONFIG_CERTIFICATE;
    } else if (network_size <= devices_by_datarate[index].max_for_small) {
        return CONFIG_SMALL;
    } else if (network_size <= devices_by_datarate[index].max_for_medium) {
        return CONFIG_MEDIUM;
    } else if (network_size <= devices_by_datarate[index].max_for_large) {
        return CONFIG_LARGE;
    }
    return CONFIG_XLARGE;
}

int8_t ws_cfg_network_size_set(struct net_if *cur, uint8_t network_size, uint8_t flags)
{
    (void) flags;
    uint8_t config_size = ws_cfg_config_get_by_size(cur, network_size);

    ws_cfg_nw_size_t nw_size_cfg;

    ws_cfg_timing_get(&nw_size_cfg.timing);
    ws_cfg_sec_prot_get(&nw_size_cfg.sec_prot);
    ws_cfg_mpl_get(&nw_size_cfg.mpl);

    ws_cfg_network_size_config_set_size set_function = NULL;

    if (config_size == CONFIG_CERTIFICATE) {
        set_function = ws_cfg_network_size_config_set_certificate;
    } else if (config_size == CONFIG_SMALL) {
        set_function = ws_cfg_network_size_config_set_small;
    } else if (config_size == CONFIG_MEDIUM) {
        set_function = ws_cfg_network_size_config_set_medium;
    } else if (config_size == CONFIG_LARGE) {
        set_function = ws_cfg_network_size_config_set_large;
    } else {
        set_function = ws_cfg_network_size_config_set_xlarge;
    }

    // Overrides the values on the new configuration
    if (set_function != NULL) {
        set_function(&nw_size_cfg);
    }

    /* Sets values if changed */
    ws_cfg_timing_set(cur, &nw_size_cfg.timing, 0x00);
    ws_cfg_sec_prot_set(cur, &nw_size_cfg.sec_prot, 0x00);
    ws_cfg_mpl_set(cur, &nw_size_cfg.mpl, 0x00);

    return CFG_SETTINGS_OK;
}

static void ws_cfg_network_size_config_set_small(ws_cfg_nw_size_t *cfg)
{
    // Configure the Wi-SUN timing trickle parameter
    cfg->timing.disc_trickle_imin = TRICKLE_IMIN_15_SECS;       // 15 seconds
    cfg->timing.disc_trickle_imax = TRICKLE_IMIN_15_SECS << 2;  // 60 seconds
    cfg->timing.disc_trickle_k = 1;
    cfg->timing.temp_link_min_timeout = WS_NEIGHBOR_TEMPORARY_LINK_MIN_TIMEOUT_SMALL;
    cfg->timing.temp_eapol_min_timeout = WS_EAPOL_TEMPORARY_ENTRY_SMALL_TIMEOUT;

    // EAPOL configuration
    cfg->sec_prot.sec_prot_trickle_imin = SEC_PROT_SMALL_IMIN;
    cfg->sec_prot.sec_prot_trickle_imax = SEC_PROT_SMALL_IMAX;
    cfg->sec_prot.sec_prot_trickle_timer_exp = SEC_PROT_TIMER_EXPIRATIONS;
    cfg->sec_prot.sec_prot_retry_timeout = SEC_PROT_RETRY_TIMEOUT_SMALL;

    // Multicast timing configuration
    cfg->mpl.mpl_trickle_imin = MPL_SMALL_IMIN;
    cfg->mpl.mpl_trickle_imax = MPL_SMALL_IMAX;
    cfg->mpl.mpl_trickle_k = MPL_SMALL_K;
    cfg->mpl.mpl_trickle_timer_exp = MPL_SMALL_EXPIRATIONS;
    cfg->mpl.seed_set_entry_lifetime = MPL_SMALL_SEED_LIFETIME;

}

static void ws_cfg_network_size_config_set_medium(ws_cfg_nw_size_t *cfg)
{
    // Configure the Wi-SUN timing trickle parameters
    cfg->timing.disc_trickle_imin = TRICKLE_IMIN_60_SECS;       // 60 seconds
    cfg->timing.disc_trickle_imax = TRICKLE_IMIN_60_SECS << 4;      // 960 seconds; 16 minutes
    cfg->timing.disc_trickle_k = 1;
    cfg->timing.temp_link_min_timeout = WS_NEIGHBOR_TEMPORARY_LINK_MIN_TIMEOUT_SMALL;
    cfg->timing.temp_eapol_min_timeout = WS_EAPOL_TEMPORARY_ENTRY_MEDIUM_TIMEOUT;

    // EAPOL configuration
    cfg->sec_prot.sec_prot_trickle_imin = SEC_PROT_SMALL_IMIN;
    cfg->sec_prot.sec_prot_trickle_imax = SEC_PROT_SMALL_IMAX;
    cfg->sec_prot.sec_prot_trickle_timer_exp = SEC_PROT_TIMER_EXPIRATIONS;
    cfg->sec_prot.sec_prot_retry_timeout = SEC_PROT_RETRY_TIMEOUT_SMALL;

    // Multicast timing configuration
    cfg->mpl.mpl_trickle_imin = MPL_MEDIUM_IMIN;
    cfg->mpl.mpl_trickle_imax = MPL_MEDIUM_IMAX;
    cfg->mpl.mpl_trickle_k = MPL_MEDIUM_K;
    cfg->mpl.mpl_trickle_timer_exp = MPL_MEDIUM_EXPIRATIONS;
    cfg->mpl.seed_set_entry_lifetime = MPL_MEDIUM_SEED_LIFETIME;
}

static void ws_cfg_network_size_config_set_large(ws_cfg_nw_size_t *cfg)
{
    // Configure the Wi-SUN timing trickle parameters
    cfg->timing.disc_trickle_imin = TRICKLE_IMIN_60_SECS << 1;       // 120 seconds
    cfg->timing.disc_trickle_imax = 1536;      // 1536 seconds; 25 minutes
    cfg->timing.disc_trickle_k = 1;
    cfg->timing.temp_link_min_timeout = WS_NEIGHBOR_TEMPORARY_LINK_MIN_TIMEOUT_LARGE;
    cfg->timing.temp_eapol_min_timeout = WS_EAPOL_TEMPORARY_ENTRY_LARGE_TIMEOUT;

    // EAPOL configuration
    cfg->sec_prot.sec_prot_trickle_imin = SEC_PROT_LARGE_IMIN;
    cfg->sec_prot.sec_prot_trickle_imax = SEC_PROT_LARGE_IMAX;
    cfg->sec_prot.sec_prot_trickle_timer_exp = SEC_PROT_TIMER_EXPIRATIONS;
    cfg->sec_prot.sec_prot_retry_timeout = SEC_PROT_RETRY_TIMEOUT_LARGE;

    // Multicast timing configuration
    cfg->mpl.mpl_trickle_imin = MPL_LARGE_IMIN;
    cfg->mpl.mpl_trickle_imax = MPL_LARGE_IMAX;
    cfg->mpl.mpl_trickle_k = MPL_LARGE_K;
    cfg->mpl.mpl_trickle_timer_exp = MPL_LARGE_EXPIRATIONS;
    cfg->mpl.seed_set_entry_lifetime = MPL_LARGE_SEED_LIFETIME;
}

static void ws_cfg_network_size_config_set_xlarge(ws_cfg_nw_size_t *cfg)
{
    // Configure the Wi-SUN timing trickle parameters
    cfg->timing.disc_trickle_imin = TRICKLE_IMIN_60_SECS << 2;       // 240 seconds
    cfg->timing.disc_trickle_imax = 1920;      // 1920 seconds; 32 minutes
    cfg->timing.disc_trickle_k = 1;
    cfg->timing.temp_link_min_timeout = WS_NEIGHBOR_TEMPORARY_LINK_MIN_TIMEOUT_LARGE;
    cfg->timing.temp_eapol_min_timeout = WS_EAPOL_TEMPORARY_ENTRY_LARGE_TIMEOUT;

    // EAPOL configuration
    cfg->sec_prot.sec_prot_trickle_imin = SEC_PROT_LARGE_IMIN;
    cfg->sec_prot.sec_prot_trickle_imax = SEC_PROT_LARGE_IMAX;
    cfg->sec_prot.sec_prot_trickle_timer_exp = SEC_PROT_TIMER_EXPIRATIONS;
    cfg->sec_prot.sec_prot_retry_timeout = SEC_PROT_RETRY_TIMEOUT_LARGE;

    // Multicast timing configuration
    cfg->mpl.mpl_trickle_imin = MPL_XLARGE_IMIN;
    cfg->mpl.mpl_trickle_imax = MPL_XLARGE_IMAX;
    cfg->mpl.mpl_trickle_k = MPL_XLARGE_K;
    cfg->mpl.mpl_trickle_timer_exp = MPL_XLARGE_EXPIRATIONS;
    cfg->mpl.seed_set_entry_lifetime = MPL_XLARGE_SEED_LIFETIME;
}

static void ws_cfg_network_size_config_set_certificate(ws_cfg_nw_size_t *cfg)
{
    // Configure the Wi-SUN timing trickle parameters
    cfg->timing.disc_trickle_imin = TRICKLE_IMIN_15_SECS;       // 15 seconds
    cfg->timing.disc_trickle_imax = TRICKLE_IMIN_15_SECS << 2;  // 60 seconds
    cfg->timing.disc_trickle_k = 1;
    cfg->timing.temp_link_min_timeout = WS_NEIGHBOR_TEMPORARY_LINK_MIN_TIMEOUT_SMALL;
    cfg->timing.temp_eapol_min_timeout = WS_EAPOL_TEMPORARY_ENTRY_SMALL_TIMEOUT;

    // EAPOL configuration
    cfg->sec_prot.sec_prot_trickle_imin = SEC_PROT_SMALL_IMIN;
    cfg->sec_prot.sec_prot_trickle_imax = SEC_PROT_SMALL_IMAX;
    cfg->sec_prot.sec_prot_trickle_timer_exp = SEC_PROT_TIMER_EXPIRATIONS;
    cfg->sec_prot.sec_prot_retry_timeout = SEC_PROT_RETRY_TIMEOUT_SMALL;

    // Multicast timing configuration for certification uses the LARGE values as it is the one mentioned ins specification
    cfg->mpl.mpl_trickle_imin = MPL_XLARGE_IMIN;
    cfg->mpl.mpl_trickle_imax = MPL_XLARGE_IMAX;
    cfg->mpl.mpl_trickle_k = MPL_XLARGE_K;
    cfg->mpl.mpl_trickle_timer_exp = MPL_XLARGE_EXPIRATIONS;
    cfg->mpl.seed_set_entry_lifetime = MPL_XLARGE_SEED_LIFETIME;
}

int8_t ws_cfg_timing_default_set(ws_timing_cfg_t *cfg)
{
    // Configure the Wi-SUN timing trickle parameters
    cfg->disc_trickle_imin = TRICKLE_IMIN_60_SECS;       // 60 seconds
    cfg->disc_trickle_imax = TRICKLE_IMIN_60_SECS << 4;  // 960 seconds; 16 minutes
    cfg->disc_trickle_k = 1;
    cfg->temp_link_min_timeout = WS_NEIGHBOR_TEMPORARY_LINK_MIN_TIMEOUT_SMALL;
    cfg->temp_eapol_min_timeout = WS_EAPOL_TEMPORARY_ENTRY_MEDIUM_TIMEOUT;

    return CFG_SETTINGS_OK;
}

int8_t ws_cfg_timing_get(ws_timing_cfg_t *cfg)
{
    *cfg = ws_cfg.timing;
    return CFG_SETTINGS_OK;
}

int8_t ws_cfg_timing_validate(ws_timing_cfg_t *new_cfg)
{
    ws_timing_cfg_t *cfg = &ws_cfg.timing;

    if (cfg->disc_trickle_imin != new_cfg->disc_trickle_imin ||
            cfg->disc_trickle_imax != new_cfg->disc_trickle_imax ||
            cfg->disc_trickle_k != new_cfg->disc_trickle_k ||
            cfg->temp_link_min_timeout != new_cfg->temp_link_min_timeout) {

        // Discovery Imin 1 to 255
        if (new_cfg->disc_trickle_imin < 1 || new_cfg->disc_trickle_imin > 255) {
            return CFG_SETTINGS_ERROR_TIMING_CONF;
        }
        // Discovery Imax, 1 to 8 doublings of imin
        if (new_cfg->disc_trickle_imax < new_cfg->disc_trickle_imin * 2 ||
                new_cfg->disc_trickle_imax > new_cfg->disc_trickle_imin * 256) {
            return CFG_SETTINGS_ERROR_TIMING_CONF;
        }
        // Discovery k parameter defined to be 1
        if (cfg->disc_trickle_k != 1) {
            return CFG_SETTINGS_ERROR_TIMING_CONF;
        }

        return CFG_SETTINGS_CHANGED;
    }

    return CFG_SETTINGS_OK;
}

int8_t ws_cfg_timing_set(struct net_if *cur, ws_timing_cfg_t *new_cfg, uint8_t flags)
{
    (void) flags;

    int8_t ret = ws_cfg_timing_validate(new_cfg);
    if (!(flags & CFG_FLAGS_BOOTSTRAP_SET_VALUES) && ret != CFG_SETTINGS_CHANGED) {
        return ret;
    }

    if (cur) {
        cur->ws_info.mngt.trickle_params.Imin = new_cfg->disc_trickle_imin;
        cur->ws_info.mngt.trickle_params.Imax = new_cfg->disc_trickle_imax;
        cur->ws_info.mngt.trickle_params.k = new_cfg->disc_trickle_k;
        cur->ws_info.mngt.trickle_params.TimerExpirations = TRICKLE_EXPIRATIONS_INFINITE;
        ws_pae_controller_configure(cur, NULL, NULL, new_cfg);
    }

    if (flags & CFG_FLAGS_BOOTSTRAP_SET_VALUES) {
        return CFG_SETTINGS_OK;
    }

    ws_timing_cfg_t *cfg = &ws_cfg.timing;

    *cfg = *new_cfg;

    return CFG_SETTINGS_OK;
}

static int8_t ws_cfg_mpl_default_set(ws_mpl_cfg_t *cfg)
{
    // MPL configuration
    cfg->mpl_trickle_imin = MPL_MEDIUM_IMIN;
    cfg->mpl_trickle_imax = MPL_MEDIUM_IMAX;
    cfg->mpl_trickle_k = MPL_MEDIUM_K;
    cfg->mpl_trickle_timer_exp = MPL_MEDIUM_EXPIRATIONS;
    cfg->seed_set_entry_lifetime = MPL_MEDIUM_SEED_LIFETIME;

    return CFG_SETTINGS_OK;
}

int8_t ws_cfg_mpl_get(ws_mpl_cfg_t *cfg)
{
    *cfg = ws_cfg.mpl;
    return CFG_SETTINGS_OK;
}

int8_t ws_cfg_mpl_validate(ws_mpl_cfg_t *new_cfg)
{
    ws_mpl_cfg_t *cfg = &ws_cfg.mpl;

    // MPL configuration has changed
    if (cfg->mpl_trickle_imin != new_cfg->mpl_trickle_imin ||
            cfg->mpl_trickle_imax != new_cfg->mpl_trickle_imax ||
            cfg->mpl_trickle_k != new_cfg->mpl_trickle_k ||
            cfg->mpl_trickle_timer_exp != new_cfg->mpl_trickle_timer_exp ||
            cfg->seed_set_entry_lifetime != new_cfg->seed_set_entry_lifetime) {
        return CFG_SETTINGS_CHANGED;
    }

    return CFG_SETTINGS_OK;
}

int8_t ws_cfg_mpl_set(struct net_if *cur, ws_mpl_cfg_t *new_cfg, uint8_t flags)
{
    (void) flags;

    // In Wi-SUN Border router will have modified settings to improve reliability
    if (cur) {
        // Border router sends multiple packets to ensure start of sequence
        if (new_cfg->mpl_trickle_timer_exp < MPL_BORDER_ROUTER_MIN_EXPIRATIONS) {
            new_cfg->mpl_trickle_timer_exp = MPL_BORDER_ROUTER_MIN_EXPIRATIONS;
            // Lifetime is calculated using the original IMAX
            new_cfg->seed_set_entry_lifetime = new_cfg->mpl_trickle_imax * new_cfg->mpl_trickle_timer_exp * MPL_SAFE_HOP_COUNT;
        }
        // Border router should have shorter IMAX to speed startup
        if (new_cfg->mpl_trickle_imax > MPL_BORDER_ROUTER_MAXIMUM_IMAX) {
            new_cfg->mpl_trickle_imax = MPL_BORDER_ROUTER_MAXIMUM_IMAX;
        }
    }

    int8_t ret = ws_cfg_mpl_validate(new_cfg);
    if (!(flags & CFG_FLAGS_BOOTSTRAP_SET_VALUES) && ret != CFG_SETTINGS_CHANGED) {
        return ret;
    }

    if (cur) {
        cur->mpl_data_trickle_params.Imin = MPL_MS_TO_TICKS(new_cfg->mpl_trickle_imin * 1000);
        cur->mpl_data_trickle_params.Imax = MPL_MS_TO_TICKS(new_cfg->mpl_trickle_imax * 1000);
        cur->mpl_data_trickle_params.k = new_cfg->mpl_trickle_k;
        cur->mpl_data_trickle_params.TimerExpirations = new_cfg->mpl_trickle_timer_exp;
        cur->mpl_seed_set_entry_lifetime = new_cfg->seed_set_entry_lifetime;

        if (cur->mpl_domain) {
            // Update MPL settings
            mpl_domain_change_timing(cur->mpl_domain, &cur->mpl_data_trickle_params, cur->mpl_seed_set_entry_lifetime);
        }
    }

    if (flags & CFG_FLAGS_BOOTSTRAP_SET_VALUES) {
        return CFG_SETTINGS_OK;
    }

    ws_mpl_cfg_t *cfg = &ws_cfg.mpl;

    *cfg = *new_cfg;

    return CFG_SETTINGS_OK;
}

static int8_t ws_cfg_sec_prot_default_set(ws_sec_prot_cfg_t *cfg)
{
    cfg->sec_prot_trickle_imin = SEC_PROT_SMALL_IMIN;
    cfg->sec_prot_trickle_imax = SEC_PROT_SMALL_IMAX;
    cfg->sec_prot_trickle_timer_exp = SEC_PROT_TIMER_EXPIRATIONS;
    cfg->sec_prot_retry_timeout = SEC_PROT_RETRY_TIMEOUT_SMALL;

    return CFG_SETTINGS_OK;
}

int8_t ws_cfg_sec_prot_get(ws_sec_prot_cfg_t *cfg)
{
    *cfg = ws_cfg.sec_prot;
    return CFG_SETTINGS_OK;
}

int8_t ws_cfg_sec_prot_validate(ws_sec_prot_cfg_t *new_cfg)
{
    ws_sec_prot_cfg_t *cfg = &ws_cfg.sec_prot;

    if (cfg->sec_prot_trickle_imin != new_cfg->sec_prot_trickle_imin ||
            cfg->sec_prot_trickle_imax != new_cfg->sec_prot_trickle_imax ||
            cfg->sec_prot_trickle_timer_exp != new_cfg->sec_prot_trickle_timer_exp ||
            cfg->sec_prot_retry_timeout != new_cfg->sec_prot_retry_timeout) {

        return CFG_SETTINGS_CHANGED;
    }

    return CFG_SETTINGS_OK;
}

int8_t ws_cfg_sec_prot_set(struct net_if *cur, ws_sec_prot_cfg_t *new_cfg, uint8_t flags)
{
    (void) flags;

    int8_t ret = ws_cfg_sec_prot_validate(new_cfg);
    if (!(flags & CFG_FLAGS_BOOTSTRAP_SET_VALUES) && ret != CFG_SETTINGS_CHANGED) {
        return ret;
    }

    if (cur) {
        ws_pae_controller_configure(cur, NULL, new_cfg, NULL);
    }

    if (flags & CFG_FLAGS_BOOTSTRAP_SET_VALUES) {
        return CFG_SETTINGS_OK;
    }

    ws_sec_prot_cfg_t *cfg = &ws_cfg.sec_prot;

    *cfg = *new_cfg;

    return CFG_SETTINGS_OK;
}

int8_t ws_cfg_settings_init(void)
{
    ws_cfg_settings_default_set();
    return CFG_SETTINGS_OK;
}

int8_t ws_cfg_settings_default_set(void)
{
    int8_t ret_value = 0;

    // Set default configuration values
    for (uint8_t index = 0; index < CFG_CB_NUM; index++) {
        if (cfg_cb[index].default_set) {
            if (cfg_cb[index].default_set(
                        ((uint8_t *)&ws_cfg) + cfg_cb[index].setting_offset) < 0) {
                ret_value = CFG_SETTINGS_OTHER_ERROR;
            }
        }
    }

    // Set new configuration values
    for (uint8_t index = 0; index < CFG_CB_NUM; index++) {
        if (cfg_cb[index].set(NULL,
                              ((uint8_t *)&ws_cfg) + cfg_cb[index].setting_offset,
                              0x00) < 0) {
            tr_info("FATAL CONFIG FAILURE");
            ret_value = CFG_SETTINGS_OTHER_ERROR;
        }
    }

    return ret_value;
}

int8_t ws_cfg_settings_interface_set(struct net_if *cur)
{
    int8_t ret_value = 0;

    cur->ws_info.cfg = &ws_cfg;

    // Set new configuration values
    for (uint8_t index = 0; index < CFG_CB_NUM; index++) {
        // Validation
        if (cfg_cb[index].set) {
            if (cfg_cb[index].set(cur,
                                  ((uint8_t *)&ws_cfg) + cfg_cb[index].setting_offset,
                                  CFG_FLAGS_BOOTSTRAP_SET_VALUES) < 0) {
                tr_info("FATAL CONFIG FAILURE");
                ret_value = CFG_SETTINGS_OTHER_ERROR;
            }
        }
    }

    return ret_value;
}
