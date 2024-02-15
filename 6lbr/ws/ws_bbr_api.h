/*
 * Copyright (c) 2017-2021, Pelion and affiliates.
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

/**
 * \file ws_bbr_api.h
 * \brief Wi-SUN backbone border router (BBR) application interface.
 *
 * This is Wi-SUN backbone Border router service.
 * When started the module takes care of starting the
 * components that enables default border router functionality in Wi-SUN network.
 *
 */

#ifndef WS_BBR_API_H_
#define WS_BBR_API_H_
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>

extern uint16_t test_pan_size_override;
struct net_if;

/**
 * \brief Struct route_info is parent child relation structure.
 */
typedef struct bbr_route_info {
    /** IID of target device public IPv6 address can be formed by combining prefix + IID*/
    uint8_t target[8];
    /** IID of parent*/
    uint8_t parent[8];
} bbr_route_info_t;

/**
 * Routing table get
 *
 * Table is Parent child relation using the Global address IID of the devices
 * To get the full IPv6 address of the device.
 *  IPv6 = Global Prefix + IID.
 *
 * Routing table is in the format: 16 bytes per entry
 * | Node IID 8 bytes   | parent IID 8 bytes |
 * | 1122112211221122   | 1111111111111111   |
 * | 1133113311331133   | 1111111111111111   |
 * | 1144114411441144   | 1111111111111111   |
 * | 1155115511551155   | 1122112211221122   |
 * | 1166116611661166   | 1122112211221122   |
 * | 1177117711771177   | 1155115511551155   |
 * | 1188118811881188   | 1177117711771177   |
 *
 * Order is not assured only parent child link is given in random order,
 *
 * When preparing to call this function ws_bbr_info_get function should be called to get the amount of devices in the network.
 * Memory for table is allocated based on the size of network and needs to be sizeof(bbr_route_info_t) * amount of entries.
 *
 * Return value is amount of route entries written to the table.
 *
 * \param interface_id interface ID of the Wi-SUN network.
 * \param table_ptr Application allocated memory where routing table is written.
 * \param table_len Length of the table allocated by application given as amount of entries.
 *
 * \return 0 - x on success indicates amount of Route entries written to the table_ptr
 * \return <0 in case of errors
 *
 */
int ws_bbr_routing_table_get(int8_t interface_id, bbr_route_info_t *table_ptr, uint16_t table_len);

/**
 * Sets PAN configuration
 *
 * Sets PAN configuration parameters.
 *
 * \param interface_id Network interface ID.
 * \param pan_id PAN ID; 0xffff default, generate the PAN ID.
 *
 * \return 0, PAN configuration set.
 * \return <0 PAN configuration set failed.
 */
int ws_bbr_pan_configuration_set(int8_t interface_id, uint16_t pan_id);

int ws_bbr_set_mode_switch(int8_t interface_id, int mode, uint8_t phy_mode_id, uint8_t * neighbor_mac_address);

void ws_bbr_pan_version_increase(struct net_if *cur);
void ws_bbr_lfn_version_increase(struct net_if *cur);

uint16_t ws_bbr_pan_size(struct net_if *cur);

bool ws_bbr_backbone_address_get(struct net_if *cur, uint8_t *address);

uint16_t ws_bbr_bsi_generate(void);
uint16_t ws_bbr_pan_id_get(struct net_if *interface);
void ws_bbr_init(struct net_if *interface);
void ws_bbr_nvm_info_read(uint16_t *bsi, uint16_t *pan_id);
void ws_bbr_nvm_info_write(uint16_t bsi, uint16_t pan_id);


#endif
