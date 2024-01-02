/*
 * Copyright (c) 2016-2018, Pelion and affiliates.
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
#ifndef NIST_KW_H
#define NIST_KW_H
#include <stdint.h>
#include <stddef.h>

/*
 * Implement Key Wrapping (KW) as defined in NIST SP 800-38F (using AES as
 * cipher).
 *
 * The code is only a wrapper around mbedtls_nist_kw_wrap() and
 * mbedtls_nist_kw_unwrap(). Parameters are described in nist_kw.h of mbedtls.
 *
 * The functions return a negative value on error or number of bytes in "output"
 * buffer on success.
 */

int nist_kw_unwrap(const uint8_t *key, size_t key_bits,
                   const uint8_t *input, size_t input_size,
                   uint8_t *output, size_t output_size);
int nist_kw_wrap(const uint8_t *key, size_t key_bits,
                 const uint8_t *input, size_t input_size,
                 uint8_t *output, size_t output_size);

#endif
