/*
 * Copyright (c) 2016-2019, Pelion and affiliates.
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

#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include "common/ns_list.h"

#include "net/protocol.h"
#include "common/specs/ipv6.h"
#include "ws/ws_config.h"
#include "security/protocols/sec_prot_keys.h"

#include "security/protocols/sec_prot_certs.h"

// Length for PEM coded certificate's begin and end certificate text strings
#define SEC_PROT_CERT_PEM_HEADER_FOOTER_LEN                52
#define SEC_PROT_CERT_PEM_HEADER_STR                       "-----BEGIN CERTIFICATE-----"

int8_t sec_prot_certs_init(sec_prot_certs_t *certs)
{
    if (!certs) {
        return -1;
    }

    sec_prot_certs_chain_entry_init(&certs->own_cert_chain);
    ns_list_init(&certs->trusted_cert_chain_list);
    certs->own_cert_chain_len = 0;
    certs->ext_cert_valid_enabled = false;

    return 0;
}

int8_t sec_prot_certs_ext_certificate_validation_set(sec_prot_certs_t *certs, bool enabled)
{
    if (!certs) {
        return -1;
    }

    certs->ext_cert_valid_enabled = enabled;

    return 0;
}

bool sec_prot_certs_ext_certificate_validation_get(const sec_prot_certs_t *certs)
{
    return certs->ext_cert_valid_enabled;
}

uint16_t sec_prot_certs_own_cert_chain_len_get(const sec_prot_certs_t *certs)
{
    return certs->own_cert_chain_len;
}

cert_chain_entry_t *sec_prot_certs_chain_entry_create(void)
{
    cert_chain_entry_t *entry = malloc(sizeof(cert_chain_entry_t));
    if (!entry) {
        return NULL;
    }
    sec_prot_certs_chain_entry_init(entry);
    return entry;
}

void sec_prot_certs_chain_entry_init(cert_chain_entry_t *entry)
{
    memset(entry, 0, sizeof(cert_chain_entry_t));
}

void sec_prot_certs_chain_entry_delete(cert_chain_entry_t *entry)
{
    free(entry);
}

int8_t sec_prot_certs_cert_set(cert_chain_entry_t *entry, uint8_t index, uint8_t *cert, uint16_t cert_len)
{
    if (!entry || index >= SEC_PROT_CERT_CHAIN_DEPTH) {
        return -1;
    }

    entry->cert[index] = cert;
    entry->cert_len[index] = cert_len;

    return 0;
}

uint8_t *sec_prot_certs_cert_get(const cert_chain_entry_t *entry, uint8_t index, uint16_t *cert_len)
{
    if (!entry || index >= SEC_PROT_CERT_CHAIN_DEPTH || !entry->cert[index]) {
        return NULL;
    }

    *cert_len = entry->cert_len[index];
    return entry->cert[index];
}

uint16_t sec_prot_certs_cert_chain_entry_len_get(const cert_chain_entry_t *entry)
{
    uint16_t chain_length = 0;
    for (uint8_t index = 0; index < SEC_PROT_CERT_CHAIN_DEPTH; index++) {
        if (entry->cert[index]) {
            uint16_t cert_length  = entry->cert_len[index];
            // Checks if certificate is in PEM base64 format
            if (cert_length > SEC_PROT_CERT_PEM_HEADER_FOOTER_LEN &&
                    entry->cert[index][cert_length - 1] == '\0' &&
                    strstr((const char *)entry->cert[index], SEC_PROT_CERT_PEM_HEADER_STR) != NULL) {
                cert_length -= SEC_PROT_CERT_PEM_HEADER_FOOTER_LEN;
                /* 4 base64 chars encode 3 bytes (ignores line endings and possible paddings in the
                   calculation i.e they are counted to length) */
                chain_length += (cert_length / 4) * 3;
            } else {
                chain_length += cert_length;
            }
        }
    }
    return chain_length;
}

int8_t sec_prot_certs_priv_key_set(cert_chain_entry_t *entry, uint8_t *key, uint8_t key_len)
{
    if (!entry) {
        return -1;
    }

    entry->key = key;
    entry->key_len = key_len;

    return 0;
}

uint8_t *sec_prot_certs_priv_key_get(const cert_chain_entry_t *entry, uint8_t *key_len)
{
    if (!entry) {
        return NULL;
    }
    *key_len = entry->key_len;
    return entry->key;
}

void sec_prot_certs_chain_list_add(cert_chain_list_t *cert_chain_list, cert_chain_entry_t *entry)
{
    ns_list_add_to_end(cert_chain_list, entry);
}

void sec_prot_certs_chain_list_delete(cert_chain_list_t *chain_list)
{
    ns_list_foreach_safe(cert_chain_entry_t, entry, chain_list) {
        ns_list_remove(chain_list, entry);
        free(entry);
    }
}

cert_chain_entry_t *sec_prot_certs_chain_list_entry_find(cert_chain_list_t *chain_list, cert_chain_entry_t *entry)
{
    ns_list_foreach(cert_chain_entry_t, list_entry, chain_list) {
        bool match = true;
        for (uint8_t i = 0; i < SEC_PROT_CERT_CHAIN_DEPTH; i++) {
            if (list_entry->cert_len[i] != entry->cert_len[i]) {
                match = false;
                break;
            }
            if (memcmp(list_entry->cert[i], entry->cert[i], list_entry->cert_len[i]) != 0) {
                match = false;
                break;
            }
        }
        if (match) {
            return list_entry;
        }
    }
    return NULL;
}
