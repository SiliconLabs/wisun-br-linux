/*
 * Copyright (c) 2015-2017, 2020, Pelion and affiliates.
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

/*
 * \file lowpan_context.c
 * \brief API for Add,Remove and update timeouts for lowpan context's
 *
 */
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include "common/bits.h"
#include "common/log_legacy.h"
#include "common/ns_list.h"
#include "net/protocol.h"

#include "6lowpan/iphc_decode/lowpan_context.h"

#define TRACE_GROUP "lCon"

lowpan_context_t *lowpan_context_get_by_id(const lowpan_context_list_t *list, uint8_t id)
{
    id &=  LOWPAN_CONTEXT_CID_MASK;
    /* Check to see we already have info for this context */
    ns_list_foreach(lowpan_context_t, entry, list) {
        if (entry->cid == id) {
            return entry;
        }
    }
    return NULL;
}

lowpan_context_t *lowpan_context_get_by_address(const lowpan_context_list_t *list, const uint8_t *ipv6Address)
{
    /* Check to see we already have info for this context
     * List is already listed that longest prefix are first at list
     */
    ns_list_foreach(lowpan_context_t, entry, list) {
        if (!bitcmp(entry->prefix, ipv6Address, entry->length)) {
            //Take always longest match prefix
            return entry;
        }
    }
    return NULL;
}

void lowpan_context_list_free(lowpan_context_list_t *list)
{
    ns_list_foreach_safe(lowpan_context_t, cur, list) {
        ns_list_remove(list, cur);
        free(cur);
    }
}

/* ticks is in 1/10s */
void lowpan_context_timer(int ticks)
{
    struct net_if *interface = protocol_stack_interface_info_get();
    lowpan_context_list_t *list = &interface->lowpan_contexts;

    ns_list_foreach_safe(lowpan_context_t, ctx, list) {
        if (ctx->lifetime > ticks) {
            ctx->lifetime -= ticks;
            continue;
        }
        if (!ctx->expiring) {
            /* Main lifetime has run out. Clear compression flag, and retain a
             * bit longer (RFC 6775 5.4.3).
             */
            ctx->compression = false;
            ctx->expiring = true;
            ctx->lifetime = 2 * 18000u; /* 2 * default Router Lifetime = 2 * 1800s = 1 hour */
            tr_debug("Context timed out - compression disabled");
        } else {
            /* 1-hour expiration timer set above has run out */
            ns_list_remove(list, ctx);
            free(ctx);
            tr_debug("Delete Expired context");
        }
    }
}

