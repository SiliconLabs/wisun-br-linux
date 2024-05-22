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
 *
 */
#ifndef SPECS_NDP_H
#define SPECS_NDP_H

// IPv6 Neighbor Discovery Option Formats
// https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml#icmpv6-parameters-5
enum {
    NDP_OPT_SLLAO =  1, // Source Link-Layer Address Option
    NDP_OPT_TLLAO =  2, // Target Link-Layer Address Option
    // ...
    NDP_OPT_ARO   = 33, // Address Registration Option
};

#endif
