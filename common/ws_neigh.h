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
#include "common/timer.h"
#include "common/ws_chan_mask.h"
#include "common/ws_ie.h"

#define WS_NEIGHBOUR_TEMPORARY_ENTRY_LIFETIME 600
#define WS_NEIGHBOR_LINK_TIMEOUT 2200

struct ws_fhss_config;

struct ws_neigh_fhss {
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
    uint8_t  uc_channel_list[WS_CHAN_MASK_LEN]; // Neighbor unicast channel list
};

struct lto_info {
    uint24_t uc_interval_min_ms;    // from NR-IE
    uint24_t uc_interval_max_ms;    // from NR-IE
    bool offset_adjusted;
};

struct ws_neigh {
    /**
     * Theses fields were introduced to differentiate FHSS data read in secured
     * frames and FHSS data read in unsecured frames.
     * However, various conception issues from the Wi-SUN specification lead us
     * to always use unsecured information:
     *   - LFNs may never send an LCP-IE along with secured frames which forces
     *     us to use unsecured information. Note that an attacker could easily
     *     send this IE in an unsecured frame (LPAS or EAPOL) and change the
     *     information of an authenticated LFN that has never sent a secured
     *     frame with LCP-IE (DDOS attack).
     *   - When keys turn, LFNs may change their UC interval to speed up the
     *     EAPOL process but do not have to send any secured frame afterward,
     *     which means that the unsecured FHSS data must be used until they
     *     do so.
     * Generally speaking, DDOS attacks on wireless services can be considered
     * easy. Knowing that, having these two fields is not necessary as many
     * other security breaches exist and creates other issues linked to
     * conception issues.
     */
    struct ws_neigh_fhss fhss_data;
    struct ws_neigh_fhss fhss_data_unsecured;

    float rsl_in_dbm;                                          /*!< RSL EWMA heard from neighbour*/
    float rsl_in_dbm_unsecured;                                /*!< RSL EWMA heard from neighbour*/
    float rsl_out_dbm;                                         /*!< RSL EWMA heard by neighbour*/
    uint8_t last_dsn;
    int rx_power_dbm;
    int rx_power_dbm_unsecured;
    int lqi;
    int lqi_unsecured;
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

    /*
     * TX power used for Adaptive Power Control (APC).
     * - Different Power Amplifiers (PA) can be used for different modulations.
     * - RAIL sets the average TX power, but APC controls the peak power, and
     *   average-to-peak varies greatly with the modulation used.
     */
    int8_t apc_txpow_dbm;
    int8_t apc_txpow_dbm_ofdm;

    // TODO: Support ETX computation with mode switch as per FAN 1.1
    float etx;
    int etx_tx_cnt;
    int etx_ack_cnt;
    struct timer_entry etx_timer_compute;
    struct timer_entry etx_timer_outdated;

    uint8_t edfe_mode;
    bool trusted_device: 1;                                /*!< True mean use normal group key, false for enable pairwise key */
    struct timer_entry timer;
    SLIST_ENTRY(ws_neigh) link;
};
SLIST_HEAD(ws_neigh_list, ws_neigh);

/**
 * Neighbor hopping info data base
 */
struct ws_neigh_table {
    struct timer_group timer_group;
    struct ws_neigh_list neigh_list;
    void (*on_add)(struct ws_neigh_table *table, struct ws_neigh *neigh);
    void (*on_del)(struct ws_neigh_table *table, struct ws_neigh *neigh);

    // Called when ETX is out-of-date. This should initiate some traffic in
    // order to measure ETX.
    void (*on_etx_outdated)(struct ws_neigh_table *table, struct ws_neigh *neigh);
};

struct ws_neigh *ws_neigh_get(struct ws_neigh_table *table, const uint8_t *mac64);

void ws_neigh_del(struct ws_neigh_table *table, const uint8_t *mac64);

// Unicast Timing update
void ws_neigh_ut_update(struct ws_neigh_fhss *fhss_data, uint24_t ufsi,
                        uint64_t tstamp_us, const uint8_t eui64[8]);
// LFN Unicast timing update
void ws_neigh_lut_update(struct ws_neigh_fhss *fhss_data,
                         uint16_t slot_number, uint24_t interval_offset,
                         uint64_t tstamp_us);
// LFN Network Discovery update
void ws_neigh_lnd_update(struct ws_neigh_fhss *fhss_data, const struct ws_lnd_ie *ie_lnd, uint64_t tstamp_us);

// Unicast Schedule update
void ws_neigh_us_update(const struct ws_fhss_config *fhss_config, struct ws_neigh_fhss *fhss_data,
                        const struct ws_generic_channel_info *chan_info,
                        uint8_t dwell_interval);
// LFN Unicast Schedule update
bool ws_neigh_lus_update(const struct ws_fhss_config *fhss_config,
                         struct ws_neigh_fhss *fhss_data,
                         const struct ws_generic_channel_info *chan_info,
                         uint24_t listen_interval_ms, const struct lto_info *lto_info);

uint24_t ws_neigh_calc_lfn_adjusted_interval(uint24_t bc_interval, uint24_t uc_interval,
                                             uint24_t uc_interval_min, uint24_t uc_interval_max);

uint24_t ws_neigh_calc_lfn_offset(uint24_t adjusted_listening_interval, uint32_t bc_interval);

// Node Role update (LFN only)
void ws_neigh_nr_update(struct ws_neigh *neigh, struct ws_nr_ie *nr_ie);

bool ws_neigh_duplicate_packet_check(struct ws_neigh *neigh, uint8_t mac_dsn, uint64_t rx_timestamp);

int ws_neigh_lfn_count(struct ws_neigh_table *table);

struct ws_neigh *ws_neigh_add(struct ws_neigh_table *table,
                             const uint8_t mac64[8],
                             uint8_t role, int8_t tx_power_dbm,
                             unsigned int key_index_mask);

size_t ws_neigh_get_neigh_count(struct ws_neigh_table *table);

void ws_neigh_trust(struct ws_neigh_table *table, struct ws_neigh *neigh);

void ws_neigh_refresh(struct ws_neigh_table *table, struct ws_neigh *neigh, uint32_t lifetime_s);

// Must be called when a data transmission request is finished.
void ws_neigh_etx_update(struct ws_neigh_table *table,
                         struct ws_neigh *neigh,
                         int tx_count, bool ack);

float ws_neigh_ewma_next(float cur, float val);

#endif
