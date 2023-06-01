/*
 * Copyright (c) 2020, Pelion and affiliates.
 * Copyright (c) 2021-2023 Silicon Laboratories Inc. (www.silabs.com)
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef WS_PAE_KEY_STORAGE_H_
#define WS_PAE_KEY_STORAGE_H_
#include <stdint.h>
#include <stdbool.h>

/*
 * Port access entity key storage functions.
 *
 */

// Interval to check if storage has been modified and needs to be updated to NVM
#define DEFAULT_STORING_INTERVAL                   3600

struct supp_entry;
struct sec_prot_gtk_keys;
struct sec_prot_certs;

/**
 * ws_pae_key_storage_supp_write writes supplicant entry to key storage
 *
 * \param instance instance
 * \param pae_supp supplicant entry
 *
 * \return < 0 failure
 * \return >= 0 success
 *
 */
int8_t ws_pae_key_storage_supp_write(const void *instance, struct supp_entry *pae_supp);

/**
 * ws_pae_key_storage_supp_read reads supplicant entry from key storage
 *
 * \param instance instance
 * \param eui_64 EUI-64 of the supplicant
 * \param gtks GTK keys
 * \param cert_chain certificates
 *
 * \return supplicant entry or NULL if supplicant entry does not exits
 *
 */
struct supp_entry *ws_pae_key_storage_supp_read(const void *instance, const uint8_t *eui_64, struct sec_prot_gtk_keys *gtks, struct sec_prot_gtk_keys *lgtks, const struct sec_prot_certs *certs);

/**
 * ws_pae_key_storage_supp_delete delete supplicant entry from key storage
 *
 * \param instance instance
 * \param eui_64 EUI-64 of the supplicant
 *
 * \return true entry was deleted
 * \return false entry was not deleted
 *
 */
bool ws_pae_key_storage_supp_delete(const void *instance, const uint8_t *eui64);

/**
 * ws_pae_key_storage_storing_interval_get gets key storage storing interval
 *
 * \return storing interval in seconds
 *
 */
uint16_t ws_pae_key_storage_storing_interval_get(void);

int ws_pae_key_storage_list(uint8_t eui64[][8], int len);
bool ws_pae_key_storage_supp_exists(const uint8_t eui64[8]);

#endif
