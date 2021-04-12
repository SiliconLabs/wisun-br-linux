/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
#ifndef WSBR_FHSS_NET_H
#define WSBR_FHSS_NET_H

#include "nanostack/fhss_ws_extension.h"
#include "nanostack/net_fhss.h"

#define FHSS_API_PLACEHOLDER ((struct fhss_api *) 0xbadbeef)

void ns_fhss_ws_set_neighbor(const struct fhss_api *fhss_api, const uint8_t eui64[8],
                             fhss_ws_neighbor_timing_info_t *fhss_data);

#endif

