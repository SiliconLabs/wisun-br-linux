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

#include "ns_types.h"
#include "ns_list.h"
#include "nsdynmemLIB.h"
#include "randLIB.h"
#include "common_functions.h"

#include "ns_trace.h"

/**
 * Thread includes
 * */
#include "thread_config.h"
#include "thread_meshcop_lib.h"
#include "thread_management_if.h"
#include "thread_management_api.h"
#include "thread_commissioning_api.h"
#include "thread_common.h"
int thread_management_register(int8_t interface_id)
{
    (void)interface_id;
    return -1;
}

int thread_management_unregister(int8_t instance_id)
{
    (void)instance_id;
    return -1;
}

int thread_management_set_security_policy(int8_t instance_id, uint8_t options, uint16_t rotation_time, management_set_response_cb *cb_ptr)
{
    (void)instance_id;
    (void) options;
    (void)rotation_time;
    (void)cb_ptr;
    return -1;
}

int thread_management_set_steering_data(int8_t instance_id, uint16_t session_id, uint8_t *steering_data_ptr, uint8_t steering_data_len, management_set_response_cb *cb_ptr)
{
    (void)instance_id;
    (void) session_id;
    (void) steering_data_ptr;
    (void)steering_data_len;
    (void)cb_ptr;
    return -1;
}

int thread_management_set_commissioning_data_timestamp(int8_t instance_id, uint64_t time, management_set_response_cb *cb_ptr)
{
    (void)instance_id;
    (void) time;
    (void)cb_ptr;
    return -1;
}

int thread_management_get(int8_t instance_id, uint8_t dst_addr[static 16], char *uri_ptr, uint8_t *fields_ptr, uint8_t fields_count, management_get_response_cb *cb_ptr)
{
    (void) instance_id;
    (void) dst_addr;
    (void) uri_ptr;
    (void) fields_ptr;
    (void) fields_count;
    (void) cb_ptr;
    return -1;
}

int thread_management_set(int8_t instance_id, uint8_t dst_addr[static 16], char *uri_ptr, uint8_t *data_ptr, uint8_t data_len, management_set_response_cb *cb_ptr)
{
    (void) instance_id;
    (void) dst_addr;
    (void) uri_ptr;
    (void) data_ptr;
    (void) data_len;
    (void) cb_ptr;
    return -1;
}

