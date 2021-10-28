/*
 * Copyright (c) 2014-2019, Pelion and affiliates.
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

#ifndef PANA_INTERNAL_API_H_
#define PANA_INTERNAL_API_H_
#define pana_server_process_ready_cb_set(cb_fptr) -2
#define pana_get_params_ptr() NULL
#define pana_common_state_machine(suite) ((void)0)
#define pana_reset_values(pan_id) ((void)0)
#define pana_key_get(key) NULL
#define pana_server_key_material_load(interface_id) -2
#define pana_server_interface_init(interface_id,cipher_mode, key_material, time_period_before_activate_key) -2
#define pana_client_interface_init(interface_id, cipher_mode, psk_key_id) -2
#define pana_reset_client_session() ((void)0)
#define pana_client_parameter_allocate() NULL
#define pana_server_trig_new_key(interface_id) -2
#define pana_interface_certificate_chain_set(chain_info) -2
#define pana_client_key_pull(interface_id) -2
#define pana_network_key_get(interface_id, key) -2
#define pana_set_params(params) -2
#define pana_get_params(params) -2
#define pana_server_key_update(interface_id, network_key_material) -2
#define pana_ping_notify_msg_tx(pan_id) 0
#endif /* PANA_INTERNAL_API_H_ */
