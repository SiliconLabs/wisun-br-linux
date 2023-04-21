/*
 * Copyright (c) 2014-2020, Pelion and affiliates.
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

#ifndef NET_WS_TEST_H_
#define NET_WS_TEST_H_
#include <stdint.h>
#include <stdbool.h>

/* Prevent this file being inserted in public Doxygen generated file
 * this is not part of our external API. */
#ifndef DOXYGEN

/**
 * \file net_ws_test.h
 * \brief Wi-SUN Library Test API.
 *
 * \warning NOTICE! This is test API must not be used externally.
 *
 * \warning This file is not part of the version number control and can change any time.
 *
 */


/**
 * \brief Set Wi-SUN version number
 *
 * Sets the Wi-SUN protocol version.
 *      1 = Wi-SUN FAN 1.0
 *      2 = Wi-SUN FAN 1.1
 *
 * Set version to 0 to stop override and use stack default
 *
 * \param interface_id               Network Interface
 * \param version                    Wi-SUN version
 *
 * \return 0                         OK
 * \return <0                        Failure
 */

int ws_test_version_set(int8_t interface_id, uint8_t version);

/**
 * \brief Set maximum child count.
 *
 * Maximum amount of children allowed for this device
 *
 * Values above MAC neighbor table - RPL parents - temporary entries will cause undefined behaviour
 *
 * Set child count to 0xffff to stop override
 *
 * \param interface_id               Network Interface
 * \param child_count                   Pan size reported in advertisements
 *
 * \return 0                         OK
 * \return <0                        Failure
 */
int ws_test_max_child_count_set(int8_t interface_id, uint16_t child_count);

/**
 * Sets Group Transient Keys.
 *
 * Sets Group Transient Keys (GTKs). Up to four GTKs can be set (GTKs from index
 * 0 to 3). At least one GTK must be set. GTKs provided in this function call are
 * compared to current GTKs on node or border router GTK storage. If GTK is new
 * or modified it is updated to GTK storage. If GTK is same as previous one, no
 * changes are made. If GTK is NULL then it is removed from GTK storage. When a
 * new GTK is inserted or GTK is modified, GTK lifetime is set to default. If GTKs
 * are set to border router after bootstrap, border router initiates GTK update
 * to network.
 *
 * \param interface_id Network interface ID.
 * \param gtk GTK array, if GTK is not set, pointer for the index shall be NULL.
 *
 * \return 0                         GTKs are set
 * \return <0                        GTK set has failed
 */
int ws_test_gtk_set(int8_t interface_id, uint8_t *gtk[4]);
int ws_test_lgtk_set(int8_t interface_id, uint8_t *lgtk[3]);

/**
 * Sets index of active key.
 *
 * Sets index of active Group Transient Key (GTK) to border router. If index is
 * set after bootstrap, initiates dissemination of new key index to network.
 *
 * \param interface_id Network interface ID.
 * \param index Key index
 *
 * \return 0                         Active key index has been set
 * \return <0                        Active key index set has failed
 */
int ws_test_active_key_set(int8_t interface_id, uint8_t index);

/**
 * Sets Next Group Transient Keys used during GTK life cycle
 *
 * Sets next Group Transient Keys (GTKs) used during GTK life cycle. Up to four
 * GTKs can be set (GTKs from index 0 to 3). When next GTK(s) are set, border
 * router inserts GTKs from the next GTK list into use during GTK update
 * procedure.
 *
 * \param interface_id Network interface ID.
 * \param gtk GTK array, if GTK is not set, pointer for the index shall be NULL.
 *
 * \return 0                         GTKs are set
 * \return <0                        GTK set has failed
 */
int ws_test_next_gtk_set(int8_t interface_id, uint8_t *gtk[4]);
int ws_test_next_lgtk_set(int8_t interface_id, uint8_t *gtk[3]);

/**
 * Disable First EDFE data packet send.
 *
 * Made only for test purpose for test EDFE client Data wait timeout.
 *
 * \param interface_id Network interface ID.
 * \param skip True for skip first data packet false disable unused flag.
 *
 * \return 0                        Success
 * \return <0                       Failure
 */
void ws_test_skip_edfe_data_send(int8_t interface_id, bool skip);

/**
 * Drop configured EDFE data packets.
 *
 * Made only for test purpose for test EDFE data sender retry send logic.
 *
 * \param interface_id Network interface ID.
 * \param number_of_dropped_frames How many packets will be dropped.
 *
 * \return 0                        Success
 * \return <0                       Failure
 */
int8_t  ws_test_drop_edfe_data_frames(int8_t interface_id, uint8_t number_of_dropped_frames);

/**
 * Set neighbour temporary timeout value.
 *
 * Made only for test purpose for test EDFE certificatiomn test harness.
 *
 * \param interface_id Network interface ID.
 * \param temporary_lifetime 0 to disable test harness, 240-2200 enable longer temporary neighbour lifetime. Values bigger than 2200 will be capped to 2200.
 *
 * \return 0                        Success
 * \return <0                       Failure
 */
int ws_test_neighbour_temporary_lifetime_set(int8_t interface_id, uint32_t temporary_lifetime);

/* Test procedure triggers
 *
 * Example about using the triggers during bootstrap to trigger
 * messages and state transitions.
 *
 * Border Router              Node
 *
 *                            Join state 1 (select PAN)
 *
 * PROC_PA
 * ------- PAN Advertisement------------>
 *
 *                            PROC_EAPOL
 *                            Select EAPOL target
 *                            Join state 2 (authenticate)
 * <------ EAPOL authentication -------->
 *                            Join State 3 (acquire PAN configuration)
 *
 * PROC_PC
 * ------- PAN Configuration ----------->
 *                            Join state 4 (configure routing)
 *
 * PROC_DIO
 * ------- DIO ------------------------->
 *                            Neighbor discovery (NS probing for ETX)
 *                            Create RPL candidate parent set
 *
 *                            PROC_RPL
 *                            Select RPL parent
 * <------ DHCP ------------------------>
 *
 *                            PROC_DAO
 * <------ DAO --------------------------
 * ------- DAO acknowledge ------------->
 *
 *                            Join state 5 (operational)
 *
 *
 * On automatic mode the PROC_PAS, PROC_EAPOL, PROC_PCS, PROC_DIS and PROC_RPL
 * will be triggered automatically by the node during the bootstrap.
 *
 */

/**
 * @brief Test procedure triggers.
 */
typedef enum {
    PROC_DIS,       /* trigger DODAG information object solicit (node) */
    PROC_DIO,       /* trigger DODAG information object (BR, node) */
    PROC_DAO,       /* trigger Destination advertisement object (node) */

    PROC_PAS,       /* trigger PAN Advertisement Solicit (node) */
    PROC_PA,        /* trigger PAN Advertisement (BR, node) */
    PROC_PCS,       /* trigger PAN Configuration Solicit (node) */
    PROC_PC,        /* trigger PAN Configuration (BR, node) */

    PROC_EAPOL,     /* trigger EAPOL target selection (initiates authentication, node) */
    PROC_RPL,       /* trigger RPL parent selection (node) */

    PROC_AUTO_ON,   /* trigger bootstrap test procedures automatically */
    PROC_AUTO_OFF,  /* disable automatic bootstrap test procedure triggering */

    MSG_NONE
} ws_test_proc_e;

/**
 * Trigger a test procedure
 *
 * Can be used to trigger a test procedure, e.g. to send a message (DIS,
 * DIO, DAO, PAS, PS, PCS and PC) or to trigger bootstrap state change
 * on node e.g. EAPOL target selection.
 *
 * \param interface_id Network Interface ID >= 0 or -1 for Wi-SUN mesh interface
 *                     Default value is -1
 * \param procedure Triggered procedure
 * \param parameters Parameters for future extensions, shall be set to NULL
 *
 * \return 0                        Success
 * \return <0                       Failure
 */
int ws_test_procedure_trigger(int8_t interface_id, ws_test_proc_e procedure, void *parameters);

#endif /* DOXYGEN */
#endif
