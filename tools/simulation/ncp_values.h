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
#ifndef NCP_VALUES_H
#define NCP_VALUES_H

struct ncp_val {
    int ncp;
    int host;
};

// NCP to host conversion
int ncp_ntoh(int val, const struct ncp_val table[], int count);

// Host to NCP conversion
int ncp_hton(int val, const struct ncp_val table[], int count);

// NCP status from Linux errno
int ncp_status(int err);

#endif
