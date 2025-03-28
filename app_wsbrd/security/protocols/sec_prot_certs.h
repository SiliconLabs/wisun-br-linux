/*
 * Copyright (c) 2016-2020, Pelion and affiliates.
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

#ifndef SEC_PROT_CERTS_H_
#define SEC_PROT_CERTS_H_
#include <stdint.h>
#include <stdbool.h>
#include "common/ns_list.h"

/*
 * Security protocols certificate interface. This is used by security protocols to
 * access certificate information.
 *
 * Own certificate chain contains the certificate chain that is sent on TLS handshake
 * to remote end. Typically this is one certificate long, and the certificate chains
 * to root CA certificate or to intermediate certificate known to other end. It is
 * also possible to send chain longer than one certificate.
 *
 * Key on own certificate chain must be the private key of the certificate used on
 * TLS handshake.
 *
 * Trusted certificate chains contains the root CA certificates and intermediate
 * certificates chains that are used to validate remote certificates.
 *
 */

#define SEC_PROT_CERT_CHAIN_DEPTH             4

typedef struct cert_chain_entry {
    uint8_t *cert[SEC_PROT_CERT_CHAIN_DEPTH];           /**< Certificate chain (from bottom up) */
    uint16_t cert_len[SEC_PROT_CERT_CHAIN_DEPTH];       /**< Certificate chain length */
    uint8_t *key;                                       /**< Private key */
    uint8_t key_len;                                    /**< Private key length*/
    ns_list_link_t link;                                /**< Link */
} cert_chain_entry_t;

typedef NS_LIST_HEAD(cert_chain_entry_t, link) cert_chain_list_t;

typedef struct sec_prot_certs {
    cert_chain_entry_t own_cert_chain;                  /**< Own certificate chain */
    cert_chain_list_t trusted_cert_chain_list;          /**< Trusted certificate chain lists */
    uint16_t own_cert_chain_len;                        /**< Own certificate chain certificates length */
    bool ext_cert_valid_enabled : 1;                    /**< Extended certificate validation enabled */
} sec_prot_certs_t;

/**
 * sec_prot_certs_init initialize certificate information
 *
 * \param certs certificate information
 *
 * \return < 0 failure
 * \return >= 0 success
 */
int8_t sec_prot_certs_init(sec_prot_certs_t *certs);

/**
 * sec_prot_certs_ext_certificate_validation_set enable or disable extended certificate validation
 *
 * \param certs    certificate information
 * \param enabled  true to enable extended validation, false to disable
 *
 * \return < 0 failure
 * \return >= 0 success
 *
 */
int8_t sec_prot_certs_ext_certificate_validation_set(sec_prot_certs_t *certs, bool enabled);

/**
 * sec_prot_certs_ext_certificate_validation_get get extended certificate validation setting
 *
 * \param certs    certificate information
 *
 * \return true/false enabled or not
 *
 */
bool sec_prot_certs_ext_certificate_validation_get(const sec_prot_certs_t *certs);

/**
 * sec_prot_certs_own_cert_chain_len_get get length of own certificate chain
 *
 * \param certs    certificate information
 *
 * \return length of all the certificates in the own certificate chain
 */
uint16_t sec_prot_certs_own_cert_chain_len_get(const sec_prot_certs_t *certs);

/**
 * sec_prot_certs_chain_entry_create allocate memory for certificate chain entry
 *
 * \return certificate chain entry or NULL
 */
cert_chain_entry_t *sec_prot_certs_chain_entry_create(void);

/**
 * sec_prot_certs_chain_entry_init initialize certificate chain entry
 *
 * \param entry certificate chain entry
 */
void sec_prot_certs_chain_entry_init(cert_chain_entry_t *entry);

/**
 * sec_prot_certs_chain_entry_delete deletes certificate chain entry
 *
 * \param entry certificate chain entry
 */
void sec_prot_certs_chain_entry_delete(cert_chain_entry_t *entry);

/**
 * sec_prot_certs_cert_set set certificate to chain entry
 *
 * \param entry certificate chain entry
 * \param index index for certificate
 * \param cert certificate
 * \param cert_len certificate length
 *
 * \return < 0 failure
 * \return >= 0 success
 */
int8_t sec_prot_certs_cert_set(cert_chain_entry_t *entry, uint8_t index, uint8_t *cert, uint16_t cert_len);

/**
 * sec_prot_certs_cert_get get certificate from chain entry
 *
 * \param entry certificate chain entry
 * \param index index for certificate
 * \param cert_len certificate length
 *
 * \return pointer to certificate or NULL
 */
uint8_t *sec_prot_certs_cert_get(const cert_chain_entry_t *entry, uint8_t index, uint16_t *cert_len);

/**
 * sec_prot_certs_cert_chain_entry_len_get get length of certificate chain on cert chain entry
 *
 * \param entry certificate chain entry
 *
 * \return total length of all the certificates in the entry
 */
uint16_t sec_prot_certs_cert_chain_entry_len_get(const cert_chain_entry_t *entry);

/**
 * sec_prot_certs_priv_key_set set certificate (chain) private key
 *
 * \param entry certificate chain entry
 * \param key key
 * \param key_len key length
 *
 * \return < 0 failure
 * \return >= 0 success
 */
int8_t sec_prot_certs_priv_key_set(cert_chain_entry_t *entry, uint8_t *key, uint8_t key_len);

/**
 * sec_prot_certs_priv_key_get get certificate (chain) private key
 *
 * \param entry certificate chain entry
 * \param key_len key length
 *
 * \return pointer to key or NULL
 */
uint8_t *sec_prot_certs_priv_key_get(const cert_chain_entry_t *entry, uint8_t *key_len);

/**
 * sec_prot_certs_chain_list_add add certificate chain entry to certificate chain list
 *
 * \param cert_chain_list certificate chain entry list
 * \param entry certificate chain entry
 */
void sec_prot_certs_chain_list_add(cert_chain_list_t *cert_chain_list, cert_chain_entry_t *entry);

/**
 * sec_prot_certs_chain_list_entry_find finds entry from certificate chain list
 *
 * \param cert_chain_list certificate chain entry list
 * \param entry searched certificate chain entry
 *
 * \return certificate chain entry or NULL
 *
 */
cert_chain_entry_t *sec_prot_certs_chain_list_entry_find(cert_chain_list_t *chain_list, cert_chain_entry_t *entry);

#endif
