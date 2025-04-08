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
#ifndef SUPPLICANT_STORAGE_H
#define SUPPLICANT_STORAGE_H

#include <stdbool.h>

struct supp_ctx;

bool supp_storage_load(struct supp_ctx *supp);
void supp_storage_store(struct supp_ctx *supp, bool force_write);
void supp_storage_clear(void);

#endif
