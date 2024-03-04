/*
 * Copyright (c) 2018-2021, Pelion and affiliates.
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

#ifndef WS_NEIGH_H
#define WS_NEIGH_H
#include <sys/queue.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include "common/int24.h"

#include "ws/ws_common_defines.h"

struct net_if;

struct ws_channel_mask {
    uint16_t channel_count;                     // Active channels at mask
    uint8_t channel_mask[32];                   // Supported channels
};

struct fhss_ws_neighbor_timing_info {
    uint8_t clock_drift;                        // Neighbor clock drift
    uint8_t timing_accuracy;                    // Neighbor timing accuracy
    union {
        struct {
            uint8_t  uc_dwell_interval_ms;  // from US-IE
            uint24_t ufsi;                  // from UTT-IE
            uint64_t utt_rx_tstamp_us;
        } ffn;
        struct {
            uint24_t uc_listen_interval_ms; // from LUS-IE
            uint16_t uc_slot_number;        // from LUTT-IE
            uint24_t uc_interval_offset_ms; // from LUTT-IE
            uint64_t lutt_rx_tstamp_us;

            uint24_t lpa_response_delay_ms; // from LND-IE
            uint8_t  lpa_slot_duration_ms;  // from LND-IE
            uint8_t  lpa_slot_count;        // from LND-IE
            uint16_t lpa_slot_first;        // from LND-IE
            uint64_t lnd_rx_tstamp_us;
        } lfn;
    };
    uint8_t  uc_chan_func;  // from US-IE or LUS-IE/LCP-IE
    uint16_t uc_chan_count; // from US-IE or LUS-IE/LCP-IE
    uint16_t uc_chan_fixed; // from US-IE or LUS-IE/LCP-IE
    struct ws_channel_mask uc_channel_list;          // Neighbor unicast channel list
};

typedef struct eapol_temporary_info {
    uint8_t eapol_rx_relay_filter; /*!< seconds for dropping duplicate id */
    uint8_t last_rx_mac_sequency; /*!< Only compared when Timer is active */
} eapol_temporary_info_t;

struct lto_info {
    uint24_t uc_interval_min_ms;    // from NR-IE
    uint24_t uc_interval_max_ms;    // from NR-IE
    bool offset_adjusted;
};

typedef struct ws_neigh {
    struct fhss_ws_neighbor_timing_info fhss_data;
    struct fhss_ws_neighbor_timing_info fhss_data_unsecured;
    float rsl_in_dbm;                                          /*!< RSL EWMA heard from neighbour*/
    float rsl_in_dbm_unsecured;                                /*!< RSL EWMA heard from neighbour*/
    float rsl_out_dbm;                                         /*!< RSL EWMA heard by neighbour*/
    uint8_t last_DSN;
    int rssi;
    int rssi_unsecured;
    int lqi;
    bool unicast_data_rx : 1;
    struct ws_pom_ie pom_ie;
    struct lto_info lto_info;
    uint8_t node_role;
    uint32_t frame_counter_min[7];
    uint8_t mac64[8];                                      /*!< MAC64 */
    uint32_t expiration_s;
    uint32_t lifetime_s;                                   /*!< Life time in seconds */
    uint8_t ms_phy_mode_id;                                /*!< PhyModeId selected for Mode Switch with this neighbor */
    uint8_t ms_mode;                                       /*!< Mode switch mode */
    uint32_t ms_tx_count;                                  /*!< Mode switch Tx success count */ // TODO: implement fallback mechanism in wbsrd
    uint32_t ms_retries_count;                             /*!< Mode switch Tx retries */ // TODO: implement fallback mechanism in wsbrd
    bool trusted_device: 1;                                /*!< True mean use normal group key, false for enable pairwise key */
    struct eapol_temporary_info eapol_temp_info;
    SLIST_ENTRY(ws_neigh) link;
} ws_neigh_t;

SLIST_HEAD(ws_neigh_list, ws_neigh);
typedef void ws_neigh_remove_notify(const uint8_t *mac64);

/**
 * Neighbor hopping info data base
 */
typedef struct ws_neigh_table {
    struct ws_neigh_list neigh_list;
    void (*on_expire)(const uint8_t *mac64);              /*!< Neighbor Remove Callback notify */
} ws_neigh_table_t;

ws_neigh_t *ws_neigh_get(ws_neigh_table_t *table, const uint8_t *mac64);

void ws_neigh_del(ws_neigh_table_t *table, const uint8_t *mac64);

// Unicast Timing update
void ws_neigh_ut_update(struct fhss_ws_neighbor_timing_info *fhss_data, uint24_t ufsi,
                        uint64_t tstamp_us, const uint8_t eui64[8]);
// LFN Unicast timing update
void ws_neigh_lut_update(struct fhss_ws_neighbor_timing_info *fhss_data,
                         uint16_t slot_number, uint24_t interval_offset,
                         uint64_t tstamp_us, const uint8_t eui64[8]);
// LFN Network Discovery update
void ws_neigh_lnd_update(struct fhss_ws_neighbor_timing_info *fhss_data, const struct ws_lnd_ie *ie_lnd, uint64_t tstamp_us);

// Unicast Schedule update
void ws_neigh_us_update(const struct net_if *net_if, struct fhss_ws_neighbor_timing_info *fhss_data,
                        const struct ws_generic_channel_info *chan_info,
                        uint8_t dwell_interval, const uint8_t eui64[8]);
// LFN Unicast Schedule update
bool ws_neigh_lus_update(const struct net_if *net_if,
                         struct fhss_ws_neighbor_timing_info *fhss_data,
                         const struct ws_generic_channel_info *chan_info,
                         uint24_t listen_interval_ms, const struct lto_info *lto_info);

uint24_t ws_neigh_calc_lfn_adjusted_interval(uint24_t bc_interval, uint24_t uc_interval,
                                             uint24_t uc_interval_min, uint24_t uc_interval_max);

uint24_t ws_neigh_calc_lfn_offset(uint24_t adjusted_listening_interval, uint32_t bc_interval);

// Node Role update (LFN only)
void ws_neigh_nr_update(ws_neigh_t *neigh, ws_nr_ie_t *nr_ie);

bool ws_neigh_duplicate_packet_check(ws_neigh_t *neigh, uint8_t mac_dsn, uint64_t rx_timestamp);

int ws_neigh_lfn_count(ws_neigh_table_t *table);

ws_neigh_t *ws_neigh_add(ws_neigh_table_t *table,
                             const uint8_t mac64[8],
                             uint8_t role,
                             unsigned int key_index_mask);

void ws_neigh_table_expire(struct ws_neigh_table *table, int time_update);

size_t ws_neigh_get_neigh_count(ws_neigh_table_t *table);

void ws_neigh_trust(struct ws_neigh *neigh);

void ws_neigh_refresh(struct ws_neigh *neigh, uint32_t lifetime_s);

#endif
