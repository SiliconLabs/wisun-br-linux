/*
 * Copyright (c) 2017-2019, Pelion and affiliates.
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
#include <stdint.h>
#include <string.h>
#include "common/endian.h"

#include "security/pana/pana_eap_header.h"

bool eap_header_parse(const uint8_t *data_ptr, uint16_t length, eap_header_t *header)
{
    if (length < 4) {
        return false;
    }

    header->eap_code = *data_ptr++;
    header->id_seq = *data_ptr++;
    header->length = read_be16(data_ptr);
    header->type = 0;
    data_ptr += 2;
    if (header->length < length || header->length > length) {
        return false;
    }


    switch (header->eap_code) {
        case EAP_REQ:
        case EAP_RESPONSE:
            if (header->length < 5) {
                return false;
            }
            header->type = *data_ptr++;
            break;

        case EAP_SUCCESS:
        case EAP_FAILURE:
            if (header->length != 4) {
                return false;
            }
            break;

        default:
            return false;
    }
    header->data_ptr = data_ptr;
    return true;

}

uint8_t eap_header_size(uint8_t eap_code)
{
    if (eap_code == EAP_REQ || eap_code == EAP_RESPONSE) {
        return 5;
    }
    return 4;
}

uint8_t *eap_header_build(uint8_t *ptr, uint16_t data_length, uint8_t eap_code, uint8_t id_seq, uint8_t type)
{
    *ptr++ = eap_code;
    *ptr++ = id_seq;
    ptr = write_be16(ptr, data_length);
    if (eap_code == EAP_REQ || eap_code == EAP_RESPONSE) {
        *ptr++ = type;
    }
    return ptr;

}
