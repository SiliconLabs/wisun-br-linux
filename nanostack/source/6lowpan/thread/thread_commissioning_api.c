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

/*Nanostack includes*/
#include "nsconfig.h"

#include <string.h>
#include "ns_types.h"
#include "ns_list.h"
#include "ns_trace.h"
#include "nsdynmemLIB.h"
#include "randLIB.h"
#include "common_functions.h"
#include "ns_sha256.h"

/*thread includes*/
#include "thread_config.h"
#include "thread_management_if.h"
#include "thread_meshcop_lib.h"
#include "thread_management_api.h"
#include "thread_commissioning_api.h"
#include "thread_beacon.h"
/*Private includes*/
#include "6lowpan/thread/thread_common.h"
#include "6lowpan/thread/thread_management_internal.h"
#include "6lowpan/bootstraps/protocol_6lowpan.h"// Get coordinator address

#define TRACE_GROUP TRACE_GROUP_THREAD_COMMISSIONING_API
int thread_commissioning_register(int8_t interface_id, uint8_t PSKc[static 16])
{
    (void)interface_id;
    (void)PSKc;
    return -1;
}

int thread_commissioning_unregister(int8_t interface_id)
{
    (void)interface_id;
    return -1;
}

int thread_commissioning_device_add(int8_t interface_id, bool short_eui64, uint8_t EUI64[static 8], uint8_t *PSKd_ptr, uint8_t PSKd_len, thread_commissioning_joiner_finalisation_cb *joining_device_cb_ptr)
{
    (void)interface_id;
    (void)short_eui64;
    (void)EUI64;
    (void)PSKd_ptr;
    (void)PSKd_len;
    (void)joining_device_cb_ptr;
    return -1;
}

int thread_commissioning_device_delete(int8_t interface_id, uint8_t EUI64[8])
{
    (void)interface_id;
    (void)EUI64;
    return -1;
}
void *thread_commission_device_get_next(void *ptr, int8_t interface_id, bool *short_eui64, uint8_t EUI64[8], uint8_t PSKd[32], uint8_t *PSKd_len)
{
    (void)ptr;
    (void)interface_id;
    (void)short_eui64;
    (void)EUI64;
    (void)PSKd;
    (void)PSKd_len;
    return NULL;
}

int thread_commissioning_petition_keep_alive(int8_t interface_id, commissioning_state_e state)
{
    (void)interface_id;
    (void)state;
    return -1;
}

int thread_commissioning_petition_start(int8_t interface_id, char *commissioner_id_ptr, thread_commissioning_status_cb *status_cb_ptr)
{
    (void)interface_id;
    (void)commissioner_id_ptr;
    (void)status_cb_ptr;
    return -1;
}

int thread_commissioning_native_commissioner_get_connection_info(int8_t interface_id, uint8_t *address_ptr, uint16_t *port)
{
    (void)interface_id;
    (void)address_ptr;
    (void)port;
    return -1;
}

int8_t thread_commissioning_get_management_id(int8_t interface_id)
{
    (void)interface_id;
    return -1;
}

int thread_commissioning_native_commissioner_start(int8_t interface_id, thread_commissioning_native_select_cb *cb_ptr)
{
    (void)interface_id;
    (void)cb_ptr;
    return -1;
}

int thread_commissioning_native_commissioner_stop(int8_t interface_id)
{
    (void)interface_id;
    return -1;
}

int thread_commissioning_native_commissioner_connect(int8_t interface_id, thread_commissioning_link_configuration_s *link_ptr)
{
    (void)interface_id;
    (void)link_ptr;
    return -1;
}

int thread_commissioning_attach(int8_t interface_id, uint8_t *destination_address, uint16_t destination_port)
{
    (void)interface_id;
    (void)destination_address;
    (void)destination_port;
    return -1;
}

