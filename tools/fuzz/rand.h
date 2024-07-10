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
#ifndef FUZZ_RAND_H
#define FUZZ_RAND_H

#include <sys/types.h>

/*
 * This function is exported so it can be defined to something other
 * than __real_xgetrandom outside of wsbrd-fuzz (eg. in libwsbrd-ns3).
 */

ssize_t fuzz_real_getrandom(void *buf, size_t buflen, unsigned int flags);

#endif
