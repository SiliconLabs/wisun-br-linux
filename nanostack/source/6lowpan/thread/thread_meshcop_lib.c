/*
 * Copyright (c) 2015-2019, Pelion and affiliates.
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the
 *    names of its contributors may be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "nsconfig.h"

#include "thread_meshcop_lib.h"
#include "common_functions.h"
#include <string.h>
uint16_t thread_meshcop_tlv_find(const uint8_t *ptr, uint16_t length, uint8_t type, uint8_t **result_ptr)
{
    (void)ptr;
    (void)length;
    (void)type;
    (void)result_ptr;
    return 0;
}

uint8_t *thread_meshcop_tlv_data_write(uint8_t *ptr, uint8_t type, uint16_t length, const uint8_t *data)
{
    (void)ptr;
    (void)type;
    (void)length;
    (void)data;
    return NULL;
}

uint8_t *thread_meshcop_tlv_data_write_uint8(uint8_t *ptr, uint8_t type, uint8_t data)
{
    (void) ptr;
    (void)type;
    (void)data;
    return NULL;
}

uint8_t *thread_meshcop_tlv_data_write_uint16(uint8_t *ptr, uint8_t type, uint16_t data)
{
    (void) ptr;
    (void)type;
    (void)data;
    return NULL;
}

uint8_t *thread_meshcop_tlv_data_write_uint32(uint8_t *ptr, uint8_t type, uint32_t data)
{
    (void) ptr;
    (void)type;
    (void)data;
    return NULL;
}

uint8_t *thread_meshcop_tlv_data_write_uint64(uint8_t *ptr, uint8_t type, uint64_t data)
{
    (void) ptr;
    (void)type;
    (void)data;
    return NULL;
}
bool thread_meshcop_tlv_exist(const uint8_t *ptr, const uint16_t length, const uint8_t type)
{
    (void)ptr;
    (void)length;
    (void)type;
    return false;
}

int16_t thread_meshcop_tlv_length(const uint8_t *ptr, uint16_t length)
{
    (void)ptr;
    (void)length;
    return 0;
}

int16_t thread_meshcop_tlv_length_required(const uint8_t *ptr, uint16_t length)
{
    (void)ptr;
    (void)length;
    return 0;
}

const uint8_t *thread_meshcop_tlv_get_next(const uint8_t *ptr, uint16_t *length)
{
    (void)ptr;
    (void)length;
    return NULL;
}

bool thread_meshcop_tlv_list_present(const uint8_t *ptr, uint16_t length, const uint8_t *required_tlv_ptr, uint8_t required_tlv_len)
{
    (void)ptr;
    (void)length;
    (void)required_tlv_ptr;
    (void)required_tlv_len;
    return false;
}
uint16_t thread_meshcop_tlv_list_generate(const uint8_t *ptr, uint16_t length, uint8_t *result_ptr, uint16_t *result_len)
{
    (void)ptr;
    (void)length;
    (void)result_ptr;
    (void)result_len;
    return 0;
}
uint16_t thread_meshcop_tlv_list_remove(uint8_t *tlv_ptr, uint16_t tlv_len, uint8_t tlv_type)
{
    (void)tlv_ptr;
    (void)tlv_len;
    (void)tlv_type;
    return 0;
}

bool thread_meshcop_tlv_list_type_available(const uint8_t *list_ptr, uint16_t list_len, uint8_t tlv_type)
{
    (void)list_ptr;
    (void)list_len;
    (void)tlv_type;
    return false;
}

uint16_t thread_meshcop_tlv_find_next(uint8_t *tlv_ba, uint16_t tlv_ba_length, uint8_t tlv_id, uint8_t **found_tlv)
{
    (void)tlv_ba;
    (void)tlv_ba_length;
    (void)tlv_id;
    (void)found_tlv;
    return 0;
}

uint8_t thread_meshcop_tlv_data_get_uint8(const uint8_t *ptr, uint16_t length, uint8_t type, uint8_t *data_ptr)
{
    (void)ptr;
    (void)length;
    (void)type;
    (void)data_ptr;
    return 0;
}

uint8_t thread_meshcop_tlv_data_get_uint16(const uint8_t *ptr, uint16_t length, uint8_t type, uint16_t *data_ptr)
{
    (void) ptr;
    (void)length;
    (void)type;
    (void)data_ptr;
    return 0;
}

uint8_t thread_meshcop_tlv_data_get_uint32(const uint8_t *ptr, uint16_t length, uint8_t type, uint32_t *data_ptr)
{
    (void) ptr;
    (void)length;
    (void)type;
    (void)data_ptr;
    return 0;
}

uint8_t thread_meshcop_tlv_data_get_uint64(const uint8_t *ptr, uint16_t length, uint8_t type, uint64_t *data_ptr)
{
    (void) ptr;
    (void)length;
    (void)type;
    (void)data_ptr;
    return 0;
}

