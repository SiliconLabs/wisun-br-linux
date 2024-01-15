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
 * \brief Struct ws_statistics Border router dynamic information.
 */
typedef struct bbr_information {
    /** Timestamp of the the device. Can be used as version number*/
    uint64_t timestamp;
    /** Default route Link Local address of north bound router*/
    uint8_t gateway[16];
    /** Amount of devices in the network. */
    uint16_t devices_in_network;
} bbr_information_t;

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
 * Get border router information
 *
 * \param interface_id interface ID of the Wi-SUN network
 * \param info_ptr Structure given to stack where information is stored
 *
 * \return 0 on success
 * \return <0 in case of errors
 *
 */
int ws_bbr_info_get(int8_t interface_id, bbr_information_t *info_ptr);

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
 * Remove node's keys from border router
 *
 * Removes node's keys from border router i.e. Pairwise Master Key (PMK)
 * and Pairwise Transient Key (PTK). This function is used on revocation of
 * node's access procedure after authentication service is configured
 * to reject authentication attempts of the node (e.g. node's certificate is
 * revoked). Sub sequential calls to function can be used to remove several
 * nodes from border router.
 *
 * \param interface_id Network interface ID.
 * \param eui64 EUI-64 of revoked node
 *
 * \return 0, Node's keys has been removed
 * \return <0 Node's key remove has failed (e.g. unknown address)
 */
int ws_bbr_node_keys_remove(int8_t interface_id, uint8_t *eui64);

/**
 * Start revocation of node's access
 *
 * Starts revocation of node's access procedure on border router. Before
 * the call to this function, authentication service must be configured to
 * reject authentication attempts of the removed nodes (e.g. certificates
 * of the nodes are revoked). Also the keys for the nodes must be removed
 * from the border router.
 *
 * \param interface_id Network interface ID.
 *
 * \return 0, Revocation started OK.
 * \return <0 Revocation start failed.
 */
int ws_bbr_node_access_revoke_start(int8_t interface_id, bool is_lgtk, uint8_t new_gtk[16]);

/**
 * Extended certificate validation
 */
#define BBR_CRT_EXT_VALID_NONE    0x00 /**< Do not make extended validations */
#define BBR_CRT_EXT_VALID_WISUN   0x01 /**< Validate Wi-SUN specific fields */

/**
 * Sets extended certificate validation setting
 *
 * Sets extended certificate validation setting on border router. Function can be used
 * to set which fields on client certificate are validated.
 *
 * \param interface_id Network interface ID
 * \param validation Extended Certificate validation setting
 *          BBR_CRT_EXT_VALID_NONE   Do not make extended validations
 *          BBR_CRT_EXT_VALID_WISUN  Validate Wi-SUN specific fields
 *
 * \return 0 Validation setting was set
 * \return <0 Setting set failed
 */
int ws_bbr_ext_certificate_validation_set(int8_t interface_id, uint8_t validation);

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

int ws_bbr_eapol_relay_get_socket_fd();
int ws_bbr_eapol_auth_relay_get_socket_fd();
void ws_bbr_eapol_relay_socket_cb(int fd);
void ws_bbr_eapol_auth_relay_socket_cb(int fd);

/**
 * Set RADIUS server IPv6 address
 *
 * Function sets external RADIUS server IPv6 address to Border Router. Setting the
 * address enables external RADIUS server interface on Border Router. To disable external
 * RADIUS server interface, call the function with remote address set to NULL. The RADIUS
 * shared secret must be set before address is set using ws_bbr_radius_shared_secret_set()
 * call.
 *
 * \param interface_id Network interface ID.
 * \param address Pointer to IPv6 address or NULL to disable RADIUS. Address is in binary format (16 bytes).
 *
 * \return < 0 failure
 * \return >= 0 success
 *
 */
int ws_bbr_radius_address_set(int8_t interface_id, const struct sockaddr_storage *address);

/**
 * Set RADIUS shared secret
 *
 * Function sets RADIUS shared secret to Border Router. Shared secret may be an
 * ASCII string. Check the format and length constraints for the shared secret from
 * the documentation of RADIUS server you are connecting to. Nanostack will not
 * make copy of the shared secret, therefore address and data must remain permanently
 * valid.
 *
 * \param interface_id Network interface ID.
 * \param shared_secret_len The length of the shared secret in bytes.
 * \param shared_secret Pointer to shared secret. Can be 8-bit ASCII string or byte array. Is not NUL terminated.
 *
 * \return < 0 failure
 * \return >= 0 success
 *
 */
int ws_bbr_radius_shared_secret_set(int8_t interface_id, const uint16_t shared_secret_len, const uint8_t *shared_secret);

/**
 * \brief A function to set DNS query results to border router
 *
 * Border router distributes these query results in DHCP Solicit responses to
 * all the devices joining to the Wi-SUN mesh network.
 *
 * Border router keeps these forever, but if application does not update these in regular interval
 * The address might stop working. So periodic keep alive is required.
 *
 * These cached query results will become available in the Wi-SUN interface.
 *
 * This function can be called multiple times.
 * if domain name matches a existing entry address is updated.
 * If domain name is set to NULL entire list is cleared
 * if address is set to NULL the Domain name is removed from the list.
 *
 * \param interface_id Network interface ID.
 * \param address The address of the DNS query result.
 * \param domain_name_ptr Domain name matching the address
 *
 * \return < 0 failure
 * \return >= 0 success
 */

void ws_bbr_internal_dhcp_server_start(int8_t interface_id, uint8_t *global_id);

int ws_bbr_dns_query_result_set(int8_t interface_id, const uint8_t address[16], char *domain_name_ptr);

int ws_bbr_set_phy_operating_modes(int8_t interface_id, uint8_t * phy_operating_modes, uint8_t phy_op_mode_number);

int ws_bbr_set_mode_switch(int8_t interface_id, int mode, uint8_t phy_mode_id, uint8_t * neighbor_mac_address);

void ws_bbr_pan_version_increase(struct net_if *cur);
void ws_bbr_lfn_version_increase(struct net_if *cur);

uint16_t ws_bbr_pan_size(struct net_if *cur);

bool ws_bbr_backbone_address_get(struct net_if *cur, uint8_t *address);

uint16_t ws_bbr_bsi_generate(void);
uint16_t ws_bbr_pan_id_get(struct net_if *interface);
void ws_bbr_init(struct net_if *interface);


#endif
