/*
 * Copyright (c) 2019-2021, Pelion and affiliates.
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
#include "stack-services/ns_list.h"
#include "stack-services/ns_trace.h"
#include "stack-services/common_functions.h"

#include "nwk_interface/protocol.h"
#include "security/protocols/sec_prot_certs.h"
#include "security/protocols/sec_prot_keys.h"
#include "6lowpan/ws/ws_config.h"
#include "6lowpan/ws/ws_pae_nvm_store.h"
#include "6lowpan/ws/ws_pae_controller.h"
#include "6lowpan/ws/ws_pae_time.h"

#include "6lowpan/ws/ws_pae_nvm_data.h"

#define TRACE_GROUP "wsnv"

#define PAE_NVM_FIELD_NOT_SET            0   // Field is not present
#define PAE_NVM_FIELD_SET                1   // Field is present

void ws_pae_nvm_store_keys_tlv_create(keys_nvm_tlv_t *tlv_entry, sec_prot_keys_t *sec_keys)
{
    tlv_entry->tag = PAE_NVM_KEYS_TAG;
    tlv_entry->len = PAE_NVM_KEYS_LEN;

    uint8_t *tlv = (uint8_t *) &tlv_entry->data[0];

    uint8_t *eui_64 = sec_prot_keys_ptk_eui_64_get(sec_keys);
    if (eui_64) {
        *tlv++ = PAE_NVM_FIELD_SET;
        memcpy(tlv, eui_64, 8);
    } else {
        *tlv++ = PAE_NVM_FIELD_NOT_SET;
        memset(tlv, 0, 8);
    }
    tlv += 8;

    uint8_t *pmk = sec_prot_keys_pmk_get(sec_keys);
    if (pmk) {
        *tlv++ = PAE_NVM_FIELD_SET;
        uint32_t lifetime = sec_prot_keys_pmk_lifetime_get(sec_keys);
        tlv = common_write_32_bit(lifetime, tlv);
        memcpy(tlv, pmk, PMK_LEN);
    } else {
        *tlv++ = PAE_NVM_FIELD_NOT_SET;
        memset(tlv, 0, 4 + PMK_LEN);
    }
    tlv += PMK_LEN;

    uint64_t counter = sec_prot_keys_pmk_replay_cnt_get(sec_keys);
    tlv = common_write_64_bit(counter, tlv);

    uint8_t *ptk = sec_prot_keys_ptk_get(sec_keys);
    if (ptk) {
        *tlv++ = PAE_NVM_FIELD_SET;
        uint32_t lifetime = sec_prot_keys_ptk_lifetime_get(sec_keys);
        tlv = common_write_32_bit(lifetime, tlv);
        memcpy(tlv, ptk, PTK_LEN);
    } else {
        *tlv++ = PAE_NVM_FIELD_NOT_SET;
        memset(tlv, 0, 4 + PTK_LEN);
    }
    tlv += PTK_LEN;

    tr_info("NVM KEYS write");
}

void ws_pae_nvm_store_key_storage_index_tlv_create(nvm_tlv_t *tlv_entry, uint64_t bitfield)
{
    tlv_entry->tag = PAE_NVM_KEY_STORAGE_INDEX_TAG;
    tlv_entry->len = PAE_NVM_KEY_STORAGE_INDEX_LEN;

    uint8_t *tlv = ((uint8_t *) &tlv_entry->tag) + NVM_TLV_FIXED_LEN;

    tlv = common_write_64_bit(bitfield, tlv);

    tr_info("NVM KEY STORAGE INDEX write");
}

int8_t ws_pae_nvm_store_key_storage_index_tlv_read(nvm_tlv_t *tlv_entry, uint64_t *bitfield)
{
    if (!tlv_entry || !bitfield) {
        return -1;
    }

    if (tlv_entry->tag != PAE_NVM_KEY_STORAGE_INDEX_TAG || tlv_entry->len != PAE_NVM_KEY_STORAGE_INDEX_LEN) {
        return -1;
    }

    uint8_t *tlv = ((uint8_t *) &tlv_entry->tag) + NVM_TLV_FIXED_LEN;
    *bitfield = common_read_64_bit(tlv);
    tlv += 8;

    tr_info("NVM KEY STORAGE INDEX read");

    return 0;
}

void ws_pae_nvm_store_key_storage_tlv_create(nvm_tlv_t *tlv_entry, uint16_t length)
{
    memset(tlv_entry, 0, sizeof(key_storage_nvm_tlv_entry_t));

    tlv_entry->tag = PAE_NVM_KEY_STORAGE_TAG;
    tlv_entry->len = length - sizeof(nvm_tlv_t);

    tr_debug("NVM KEY STORAGE create");
}

int8_t ws_pae_nvm_store_key_storage_tlv_read(nvm_tlv_t *tlv_entry, uint16_t length)
{
    if (!tlv_entry || !length) {
        return -1;
    }

    if (tlv_entry->tag != PAE_NVM_KEY_STORAGE_TAG || tlv_entry->len != length - sizeof(nvm_tlv_t)) {
        return -1;
    }

    tr_debug("NVM KEY STORAGE read");
    return 0;
}
