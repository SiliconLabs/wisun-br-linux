/*
 * Copyright (c) 2016-2018, 2020, Pelion and affiliates.
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
#ifndef HMAC_MD_H
#define HMAC_MD_H
#include <stdint.h>
#include <stddef.h>

/*
 * Calculate HMAC-SHA1-160 or HMAC-MD5. It is mainly used for the hash of the
 * authentication keys.
 *
 * This function is mainly a wrapper around mbedtls_md_*(). Parameters are
 * described in mbedtls/md.h.
 *
 * Returns 0 on success.
 */

int hmac_md_sha1(const uint8_t *key, size_t key_len,
                 const uint8_t *data, size_t data_len,
                 uint8_t *result, size_t result_len);
int hmac_md_md5(const uint8_t *key, size_t key_len,
                const uint8_t *data, size_t data_len,
                uint8_t *result, size_t result_len);

#endif
