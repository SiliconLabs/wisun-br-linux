/*
 * Copyright (c) 2021-2023 Silicon Laboratories Inc. (www.silabs.com)
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
#ifndef WSBR_COMMANDLINE_VALUES_H
#define WSBR_COMMANDLINE_VALUES_H

#include "common/named_values.h"

extern const struct name_value valid_ws_domains[];
extern const struct name_value valid_fsk_modulation_indexes[];
extern const struct name_value valid_ws_size[];
extern const struct name_value valid_fan_versions[];
extern const struct name_value valid_traces[];
extern const struct name_value valid_booleans[];
extern const struct name_value valid_tristate[];
extern const struct name_value valid_ws_regional_regulations[];
extern const struct name_value valid_pcapng_channel[];

#endif
