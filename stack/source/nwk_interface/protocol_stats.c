/*
 * Copyright (c) 2014-2017, 2019-2021, Pelion and affiliates.
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
#include "protocol_stats.h"

struct nwk_stats {
    /* 6Lowpan */
    uint32_t ip_rx_count;           /**< IP RX packet count. */
    uint32_t ip_tx_count;           /**< IP TX packet count. */
    uint32_t ip_rx_drop;            /**< IP RX packet drops count. */
    uint32_t ip_cksum_error;        /**< IP checksum error count. */
    /* IP Payload Flow */
    uint32_t ip_tx_bytes;           /**< IP TX bytes count. */
    uint32_t ip_rx_bytes;           /**< IP RX bytes count. */
    uint32_t ip_routed_up;          /**< IP routed UP bytes count. */
    uint32_t ip_no_route;           /**< IP no route count. */
    /* Fragments */
    uint32_t frag_rx_errors;        /**< Fragmentation RX error count. */
    uint32_t frag_tx_errors;        /**< Fragmentation TX error count. */
    /*RPL stats*/
    uint32_t rpl_route_routecost_better_change; /**< RPL parent change count. */
    uint32_t ip_routeloop_detect;               /**< RPL route loop detection count. */
    uint32_t rpl_memory_overflow;   /**< RPL memory overflow count. */
    uint32_t rpl_parent_tx_fail;    /**< RPL transmit errors to DODAG parents. */
    uint32_t rpl_unknown_instance;  /**< RPL unknown instance ID count. */
    uint32_t rpl_local_repair;      /**< RPL local repair count. */
    uint32_t rpl_global_repair;     /**< RPL global repair count. */
    uint32_t rpl_malformed_message; /**< RPL malformed message count. */
    uint32_t rpl_time_no_next_hop;  /**< RPL seconds without a next hop. */
    uint32_t rpl_total_memory;      /**< RPL current memory usage total. */
    /* Buffers */
    uint32_t buf_alloc;             /**< Buffer allocation count. */
    uint32_t buf_headroom_realloc;  /**< Buffer headroom realloc count. */
    uint32_t buf_headroom_shuffle;  /**< Buffer headroom shuffle count. */
    uint32_t buf_headroom_fail;     /**< Buffer headroom failure count. */
    /* ETX */
    uint16_t etx_1st_parent;        /**< Primary parent ETX. */
    uint16_t etx_2nd_parent;        /**< Secondary parent ETX. */
    /* MAC */
    uint16_t adapt_layer_tx_queue_size; /**< Adaptation layer direct TX queue size. */
    uint16_t adapt_layer_tx_queue_peak; /**< Adaptation layer direct TX queue size peak. */
    uint32_t adapt_layer_tx_congestion_drop; /**< Adaptation layer direct TX randon early detection drop packet. */
    uint16_t adapt_layer_tx_latency_max; /**< Adaptation layer latency between TX request and TX ready in seconds (MAX). */
};

struct nwk_stats nwk_stats = { };

void protocol_stats_update(enum nwk_stats_type type, uint16_t update_val)
{
    switch (type) {
    case STATS_IP_RX_COUNT: //RX Payload
        nwk_stats.ip_rx_count++;
        nwk_stats.ip_rx_bytes += update_val;
        break;

    case STATS_IP_ROUTE_UP:
        nwk_stats.ip_routed_up += update_val;
        /* fall through */
    case STATS_IP_TX_COUNT:
        nwk_stats.ip_tx_count++;
        nwk_stats.ip_tx_bytes += update_val;
        break;

    case STATS_IP_RX_DROP:
        nwk_stats.ip_rx_drop++;
        break;

    case STATS_IP_CKSUM_ERROR:
        nwk_stats.ip_cksum_error++;
        break;

    case STATS_FRAG_RX_ERROR:
        nwk_stats.frag_rx_errors++;
        break;

    case STATS_FRAG_TX_ERROR:
        nwk_stats.frag_tx_errors++;
        break;

    case STATS_RPL_PARENT_CHANGE:
        nwk_stats.rpl_route_routecost_better_change++;
        break;

    case STATS_RPL_ROUTELOOP:
        nwk_stats.ip_routeloop_detect++;
        break;

    case STATS_IP_NO_ROUTE:
        nwk_stats.ip_no_route++;
        break;

    case STATS_RPL_MEMORY_OVERFLOW:
        nwk_stats.rpl_memory_overflow += update_val;
        break;

    case STATS_RPL_PARENT_TX_FAIL:
        nwk_stats.rpl_parent_tx_fail += update_val;
        break;

    case STATS_RPL_UNKNOWN_INSTANCE:
        nwk_stats.rpl_unknown_instance += update_val;
        break;

    case STATS_RPL_LOCAL_REPAIR:
        nwk_stats.rpl_local_repair += update_val;
        break;

    case STATS_RPL_GLOBAL_REPAIR:
        nwk_stats.rpl_global_repair += update_val;
        break;

    case STATS_RPL_MALFORMED_MESSAGE:
        nwk_stats.rpl_malformed_message += update_val;
        break;

    case STATS_RPL_TIME_NO_NEXT_HOP:
        nwk_stats.rpl_time_no_next_hop += update_val;
        break;

    case STATS_RPL_MEMORY_ALLOC:
        nwk_stats.rpl_total_memory += update_val;
        break;

    case STATS_RPL_MEMORY_FREE:
        nwk_stats.rpl_total_memory -= update_val;
        break;

    case STATS_BUFFER_ALLOC:
        nwk_stats.buf_alloc++;
        break;

    case STATS_BUFFER_HEADROOM_REALLOC:
        nwk_stats.buf_headroom_realloc++;
        break;

    case STATS_BUFFER_HEADROOM_SHUFFLE:
        nwk_stats.buf_headroom_shuffle++;
        break;

    case STATS_BUFFER_HEADROOM_FAIL:
        nwk_stats.buf_headroom_fail++;
        break;

    case STATS_ETX_1ST_PARENT:
        nwk_stats.etx_1st_parent = update_val;
        break;

    case STATS_ETX_2ND_PARENT:
        nwk_stats.etx_2nd_parent = update_val;
        break;
    case STATS_AL_TX_QUEUE_SIZE:
        nwk_stats.adapt_layer_tx_queue_size = update_val;
        if (nwk_stats.adapt_layer_tx_queue_size > nwk_stats.adapt_layer_tx_queue_peak)
            nwk_stats.adapt_layer_tx_queue_peak = nwk_stats.adapt_layer_tx_queue_size;
        break;
    case STATS_AL_TX_CONGESTION_DROP:
        nwk_stats.adapt_layer_tx_congestion_drop++;
        break;
    case STATS_AL_TX_LATENCY:
        if (update_val > nwk_stats.adapt_layer_tx_latency_max)
            nwk_stats.adapt_layer_tx_latency_max = update_val;
        break;
    }
}
