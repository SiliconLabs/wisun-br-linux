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
#ifndef RPL_STORAGE_H
#define RPL_STORAGE_H

struct rpl_root;
struct rpl_target;

/*
 * Functions for (re)storing RPL data from/to Non-Volatile Memory (NVM).
 * A file is created per target, containing transits with the relevant data.
 */

void rpl_storage_store_config(const struct rpl_root *root);
void rpl_storage_store_target(const struct rpl_root *root, const struct rpl_target *target);
void rpl_storage_del_target(const struct rpl_root *root, const struct rpl_target *target);

void rpl_storage_load_config(struct rpl_root *root, const char *filename);
void rpl_storage_load_target(struct rpl_root *root, const char *filename);
void rpl_storage_load(struct rpl_root *root);

#endif /* RPL_STORAGE_H */
