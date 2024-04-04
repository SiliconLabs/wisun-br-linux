/*
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
#ifndef WS_CHAN_MASK_H
#define WS_CHAN_MASK_H

#include <stdint.h>

// Arbitrary value used internally. There can theoretically be more than 256
// channels, but this is currently not supported (eg. the 2.4GHz PHY).
#define WS_CHAN_MASK_LEN 32

#endif
