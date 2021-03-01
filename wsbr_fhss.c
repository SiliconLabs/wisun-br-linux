/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
/* Frequency hoping related stuff */
#include <stdio.h>

#include "mac_api.h"
#include "wsbr_fhss.h"
#include "log.h"

int ns_sw_mac_fhss_register(struct mac_api_s *mac_api, struct fhss_api *fhss_api)
{
    BUG_ON(!mac_api);
    BUG_ON(!fhss_api);

    return 0;
}

struct fhss_api *ns_sw_mac_get_fhss_api(struct mac_api_s *mac_api)
{
    BUG_ON(!mac_api);

    return NULL;
}

int ns_sw_mac_fhss_unregister(struct mac_api_s *mac_api)
{
    BUG_ON(!mac_api);

    return 0;
}

uint32_t ns_sw_mac_read_current_timestamp(struct mac_api_s *mac_api)
{
    BUG_ON(!mac_api);

    return 0;
}

int8_t ns_sw_mac_enable_frame_counter_per_key(struct mac_api_s *mac_api,
                                              bool enable_feature)
{
    BUG_ON(!mac_api);

    return 0;
}

