/*
 * SPDX-License-Identifier: LicenseRef-MSLA
 * Copyright (c) 2025 Silicon Laboratories Inc. (www.silabs.com)
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
#include <string.h>

#include "app_wsbrd/app/commandline.h"
#include "app_wsbrd/net/protocol.h"
#include "common/authenticator/authenticator.h"
#include "common/ws/eapol_relay.h"
#include "common/mbedtls_extra.h"
#include "common/string_extra.h"

#include "ws_auth.h"

void ws_auth_update_frame_counter(struct net_if *net_if, int key_index, uint32_t frame_counter)
{
    auth_update_frame_counter(net_if->auth, key_index, frame_counter);
}
