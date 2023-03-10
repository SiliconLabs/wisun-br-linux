/*
 * Copyright (c) 2021-2022 Silicon Laboratories Inc. (www.silabs.com)
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

/* Provide FHSS related functions to MAC 802.15.4 interface (located in
 * stack/source/mac/ieee802154). This bloc is now relocated to the
 * device.
 */
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include "common/iobuf.h"
#include "common/utils.h"
#include "common/spinel_defs.h"
#include "common/spinel_buffer.h"
#include "common/log.h"
#include "stack/mac/mac_api.h"

#include "wsbr.h"
#include "wsbr_mac.h"

#include "wsbr_fhss_mac.h"

