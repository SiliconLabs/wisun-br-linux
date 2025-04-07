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
#include <errno.h>
#include <sl_status.h>

#include "common/memutils.h"

#include "ncp_values.h"

int ncp_ntoh(int val, const struct ncp_val table[], int count)
{
    for (int i = 0; i < count; i++)
        if (table[i].ncp == val)
            return table[i].host;
    return -1;
}

int ncp_hton(int val, const struct ncp_val table[], int count)
{
    for (int i = 0; i < count; i++)
        if (table[i].host == val)
            return table[i].ncp;
    return -1;
}

int ncp_status(int err)
{
    static const struct ncp_val table[] = {
        { SL_STATUS_OK,                0 },
        { SL_STATUS_BUSY,              EBUSY },
        { SL_STATUS_NOT_READY,         EAGAIN },
        { SL_STATUS_NOT_SUPPORTED,     ENOTSUP },
        { SL_STATUS_ALLOCATION_FAILED, ENOMEM },
        { SL_STATUS_INVALID_PARAMETER, EINVAL },
    };
    int status;
    
    status = ncp_hton(err, table, ARRAY_SIZE(table));
    return status >= 0 ? status : SL_STATUS_FAIL;
}
