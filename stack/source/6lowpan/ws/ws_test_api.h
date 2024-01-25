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

#endif /* DOXYGEN */
#endif
