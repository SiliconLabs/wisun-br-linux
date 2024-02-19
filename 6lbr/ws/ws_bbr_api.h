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

struct net_if;

int ws_bbr_set_mode_switch(int8_t interface_id, int mode, uint8_t phy_mode_id, uint8_t * neighbor_mac_address);

void ws_bbr_init(struct net_if *interface);
void ws_bbr_nvm_info_read(uint16_t *bsi, uint16_t *pan_id, uint16_t *pan_version, uint16_t *lfn_version, char network_name[33]);
void ws_bbr_nvm_info_write(uint16_t bsi, uint16_t pan_id, uint16_t pan_version, uint16_t lfn_version, const char network_name[33]);


#endif
