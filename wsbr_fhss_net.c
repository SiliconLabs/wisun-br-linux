/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
/* Interface with nanostack/source/Service_Libs/fhss that is now relocated to
 * the device.
 */
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>

#include "nanostack/fhss_config.h"
#include "nanostack/fhss_api.h"

#include "wsbr_fhss_net.h"

#include "log.h"

struct fhss_api *ns_fhss_ws_create(const struct fhss_ws_configuration *config,
                                   const fhss_timer_t *fhss_timer)
{
    // fhss_timer is filled by wsbr_configure(). We know we know we pass -1.
    BUG_ON(fhss_timer != (fhss_timer_t *)-1);
    WARN("not implemented");

    // Upper layers absolutly want something != NULL
    return (struct fhss_api *)-1;
}

int ns_fhss_delete(struct fhss_api *fhss_api)
{
    WARN("not implemented");
    return 0;
}

const struct fhss_ws_configuration *ns_fhss_ws_configuration_get(const struct fhss_api *fhss_api)
{
    WARN("not implemented");
    return NULL;
}

int ns_fhss_ws_configuration_set(const struct fhss_api *fhss_api,
                                 const struct fhss_ws_configuration *config)
{
    WARN("not implemented");
    return 0;
}

int ns_fhss_ws_set_parent(const struct fhss_api *fhss_api, const uint8_t eui64[8],
                          const broadcast_timing_info_t *bc_timing_info, const bool force_synch)
{
    WARN("not implemented");
    return 0;
}

int ns_fhss_set_neighbor_info_fp(const struct fhss_api *fhss_api,
                                 fhss_get_neighbor_info *get_neighbor_info)
{
    WARN("not implemented");
    return 0;
}

int ns_fhss_ws_set_hop_count(const struct fhss_api *fhss_api, const uint8_t hop_count)
{
    WARN("not implemented");
    return 0;
}

