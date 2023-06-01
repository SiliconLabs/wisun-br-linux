/*
 * Copyright (c) 2010-2017, Pelion and affiliates.
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
#ifndef _NS_LIB_ADDRESS_H
#define _NS_LIB_ADDRESS_H
/**
 * \file ns_address.h
 * \brief 6LowPAN library address format description.
 *
 */
#include <stdint.h>

/**
 * /enum address_type_e
 * /brief Address types.
 */
typedef enum address_type {
    ADDRESS_IPV6,                 /**< IPv6 Address type. Must be used always at socket interface. */
    ADDRESS_IPV4,                 /**< IPv4 Address type. Must be used always at socket interface. */
    ADDRESS_TUN_DRIVER_ID         /**< Local socket address type. The length is 1 byte (driver ID for packet source). */
} address_type_e;


/**
 * /struct ns_address
 * /brief Struct for the addresses used by the socket interface functions and net_address_get().
 */
typedef struct ns_address {
    address_type_e type;          /**< Address type. */
    uint8_t address[16];          /**< Address. */
    uint16_t identifier;          /**< TCP/UDP port number. */
} ns_address_t;

#endif /* _NS_ADDRESS_H */
