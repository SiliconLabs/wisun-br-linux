/*
 * SPDX-License-Identifier: LicenseRef-MSLA
 * Copyright (c) 2023 Silicon Laboratories Inc. (www.silabs.com)
 *
 * The licensor of this software is Silicon Laboratories Inc. Your use of this
 * software is governed by the terms of the Silicon Labs Master Software License
 * Agreement (MSLA) available at [1].  This software is distributed to you in
 * Object Code format and/or Source Code format and is governed by the sections
 * of the MSLA applicable to Object Code, Source Code and Modified Open Source
 * Code. By using this software, you agree to the terms of the MSLA.
 *
 * [1]: https://www.silabs.com/about-us/legal/master-software-license-agreement
 */

#ifndef IPV6_NEIGH_STORAGE_H
#define IPV6_NEIGH_STORAGE_H

#include <stdint.h>

struct ipv6_neighbour_cache;

void ipv6_neigh_storage_save(struct ipv6_neighbour_cache *cache, const uint8_t *eui64);
void ipv6_neigh_storage_load(struct ipv6_neighbour_cache *cache);

#endif /* IPV6_NEIGH_STORAGE_H */
