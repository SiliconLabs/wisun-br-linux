/*
 * Copyright (c) 2014-2020, Pelion and affiliates.
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

/*
 * \file mac_mlme.h
 * \brief Add short description about this file!!!
 *
 */

#ifndef MAC_MLME_H_
#define MAC_MLME_H_
#include <stdint.h>
#include <stdbool.h>

struct protocol_interface_rf_mac_setup;
struct arm_event;
struct arm_device_driver_list;
struct mlme_poll;
struct mlme_reset;
struct mlme_start;
struct mlme_get_conf;
struct mlme_set;
struct channel_list;

/**
 * MLME Start Request
 *
 */
int8_t mac_mlme_start_req(const struct mlme_start *s, struct protocol_interface_rf_mac_setup *rf_mac_setup);
/**
 * MLME Reset Request
 *
 */
int8_t mac_mlme_reset(struct protocol_interface_rf_mac_setup *rf_mac_setup, const struct mlme_reset *reset);

int8_t mac_mlme_set_req(struct protocol_interface_rf_mac_setup *rf_mac_setup, const struct mlme_set *set_req);

int8_t mac_mlme_get_req(struct protocol_interface_rf_mac_setup *rf_mac_setup, struct mlme_get_conf *get_req);

void mac_extended_mac_set(struct protocol_interface_rf_mac_setup *rf_mac_setup, const uint8_t *mac64);

/**
 * MLME Poll Request
 *
 */
void mac_mlme_poll_req(struct protocol_interface_rf_mac_setup *cur, const struct mlme_poll *poll_req);

void mac_mlme_poll_process_confirm(struct protocol_interface_rf_mac_setup *rf_mac_setup, uint8_t status);

/**
 * Radio Disable and enable functions
 */
void mac_mlme_mac_radio_disabled(struct protocol_interface_rf_mac_setup *rf_mac_setup);
void mac_mlme_mac_radio_enable(struct protocol_interface_rf_mac_setup *rf_mac_set);

/**
 * Initialize MAC channel selection sequence
 *
 * TODO: initialize channel select sequence
 *       in coordinator mode
 *
 * \param new_channel channel to set
 *
 * \return 0 success
 * \return -1 HW error
 */
int8_t mac_mlme_rf_channel_change(struct protocol_interface_rf_mac_setup *rf_mac_setup, uint8_t new_channel);

void mac_mlme_event_cb(void *mac_ptr);

void mac_mlme_set_active_state(struct protocol_interface_rf_mac_setup *entry, bool new_state);

struct protocol_interface_rf_mac_setup *mac_mlme_data_base_allocate(uint8_t *mac64, struct arm_device_driver_list *dev_driver, struct mac_description_storage_size *storage_sizes, uint16_t mtu_size);
void mac_mlme_data_base_deallocate(struct protocol_interface_rf_mac_setup *rf_mac);

uint8_t mac_mlme_set_new_sqn(struct protocol_interface_rf_mac_setup *rf_setup);

uint16_t mac_mlme_get_panid(struct protocol_interface_rf_mac_setup *rf_setup);

void mac_frame_src_address_set_from_interface(uint8_t SrcAddrMode, struct protocol_interface_rf_mac_setup *rf_ptr, uint8_t *addressPtr);

uint16_t mlme_scan_analyze_next_channel(struct channel_list *mac_channel_list, bool clear_channel);

#endif
