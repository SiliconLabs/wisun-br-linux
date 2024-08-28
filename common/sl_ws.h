/*
 * SPDX-License-Identifier: LicenseRef-MSLA
 * Copyright (c) 2024 Silicon Laboratories Inc. (www.silabs.com)
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
#ifndef SL_WS_H
#define SL_WS_H

// Silicon Labs Wi-SUN Frame Types
enum {
    SL_FT_DCS = 0xf0,
    SL_FT_DCA = 0xf1,
};

// Silicon Labs Wi-SUN Header Information Element Sub-IDs
enum {
    SL_WHIE_UTT = 0,
};

#endif
