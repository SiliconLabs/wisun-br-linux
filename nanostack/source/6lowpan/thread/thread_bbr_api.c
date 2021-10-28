/*
 * Copyright (c) 2017-2020, Pelion and affiliates.
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



/*Public API control*/
int thread_bbr_start(int8_t interface_id, int8_t backbone_interface_id)
{
    (void) interface_id;
    (void) backbone_interface_id;
    return -1;
}

int thread_bbr_timeout_set(int8_t interface_id, uint32_t timeout_a, uint32_t timeout_b, uint32_t delay)
{
    (void) interface_id;
    (void) timeout_a;
    (void) timeout_b;
    (void) delay;
    return -1;
}


int thread_bbr_prefix_set(int8_t interface_id, uint8_t *prefix)
{
    (void) interface_id;
    (void) prefix;
    return -1;
}

int thread_bbr_sequence_number_set(int8_t interface_id, uint8_t sequence_number)
{
    (void) interface_id;
    (void) sequence_number;
    return -1;
}

int thread_bbr_validation_interface_address_set(int8_t interface_id, const uint8_t *addr_ptr, uint16_t port)
{
    (void) interface_id;
    (void) addr_ptr;
    (void) port;
    return -1;
}

void thread_bbr_stop(int8_t interface_id)
{
    (void) interface_id;
    return;

}
