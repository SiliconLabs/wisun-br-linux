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
#ifndef AUTHENTICATOR_STORAGE_H
#define AUTHENTICATOR_STORAGE_H

struct auth_supp_ctx;
struct auth_ctx;

bool auth_storage_load(struct auth_ctx *auth);
void auth_storage_clear_supplicant(struct auth_supp_ctx *supp);
void auth_storage_store_supplicant(struct auth_supp_ctx *supp, bool force_write);
void auth_storage_store_keys(const struct auth_ctx *auth, bool force_write);

#endif
