/*
 * Copyright (c) 2013-2017, 2019, Pelion and affiliates.
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
#include "common/log_legacy.h"
#include "common/endian.h"

#include "nwk_interface/protocol.h"
#include "nwk_interface/protocol_stats.h"
#include "common_protocols/ipv6_constants.h"
#include "common_protocols/icmpv6.h"

#include "ns_socket.h"
#include "udp.h"

/* The network stack has some inbuilt special behaviour for these known ports */

#define UDP_PORT_ECHO              7        /* Echo Protocol - RFC 862 */
#define UDP_PORT_PANA              716      /* Protocol for carrying Authentication for Network Access - RFC 5191 */
#define UDP_PORT_MLE               19788    /* Mesh Link Establishment - draft */

#define TRACE_GROUP "udp"

static buffer_t *udp_rx_security_check(buffer_t *buf)
{
    struct net_if *cur = buf->interface;
    uint8_t drop_unsecured = 0;

    // Hack for PANA and MLE. PANA socket is not unsecured, need to allow unsecured link local traffic.
    // MLE need to allow joiner request, that is not secured.
    // TODO: Check if there is better fix for these.
    if (buf->src_sa.port == UDP_PORT_PANA || buf->dst_sa.port == UDP_PORT_PANA) {
        if ((buf->dst_sa.address[0] != 0xfe)  && (buf->options.ll_security_bypass_rx)) {
            drop_unsecured = 1;
        }
    } else if (buf->dst_sa.port == UDP_PORT_MLE) {
        // OK
    } else if (buf->options.ll_security_bypass_rx) {
        if (addr_ipv6_scope(buf->src_sa.address, cur) > IPV6_SCOPE_LINK_LOCAL) {
            drop_unsecured = 1;
        } else {
            if (!buf->socket) {
                buffer_socket_set(buf, socket_lookup_ipv6(IPV6_NH_UDP, &buf->dst_sa, &buf->src_sa, true));
            }
            if (buf->socket && buf->socket->inet_pcb->link_layer_security == 0) {
                // non-secure okay if it's for a socket whose security flag is clear.
            } else {
                drop_unsecured = 1;
            }
        }
    }

    if (drop_unsecured) {
        tr_warn("Drop UDP Unsecured");
        buf = buffer_free(buf);
    }

    return buf;
}

static buffer_t *udp_checksum_check(buffer_t *buf)
{
    uint8_t *ptr = buffer_data_pointer(buf) + 6;
    uint16_t check = read_be16(ptr);

    // We refuse checksum field 0000, as per IPv6 (RFC 2460). Would have
    // to accept this if handling IPv4.
    if (check == 0 || buffer_ipv6_fcf(buf, IPV6_NH_UDP)) {
        tr_error("CKSUM ERROR - src=%s", tr_ipv6(buf->src_sa.address));
        protocol_stats_update(STATS_IP_CKSUM_ERROR, 1);
        buf = buffer_free(buf);
    }
    return buf;
}

void udp_checksum_write(buffer_t *buf)
{
    uint8_t *ptr = buffer_data_pointer(buf) + 6;
    uint16_t check;

    write_be16(ptr, 0);
    check = buffer_ipv6_fcf(buf, IPV6_NH_UDP);
    if (check == 0) {
        check = 0xffff;
    }
    write_be16(ptr, check);
}


buffer_t *udp_down(buffer_t *buf)
{
    if (buf->src_sa.addr_type != ADDR_IPV6) {
        //tr_debug("Create Address");
//      if(protocol_stack_interface_get_address_by_prefix(buf->if_index, buf->src_sa.address,buf->dst_sa.address, 0) != 0)
//      {
        tr_debug("InterFace Address Get Fail--> free Buffer");
        return buffer_free(buf);
//      }
//      else
//      {
//          buf->src_sa.addr_type = ADDR_IPV6;
//      }
    }

    buf = buffer_headroom(buf, 8);
    if (buf) {
        uint8_t *ptr;
        buf->buf_ptr -= 8;

        ptr = buffer_data_pointer(buf);
        ptr = write_be16(ptr, buf->src_sa.port);
        ptr = write_be16(ptr, buf->dst_sa.port);
        ptr = write_be16(ptr, buffer_data_length(buf));
        udp_checksum_write(buf);
        buf->IPHC_NH = 0;
        buf->info = (buffer_info_t)(B_FROM_UDP | B_TO_IPV6 | B_DIR_DOWN);
        buf->options.type = IPV6_NH_UDP;
        buf->options.code = 0;
    }
    return (buf);
}

buffer_t *udp_up(buffer_t *buf)
{
    //tr_debug("UDP UP");
    const uint8_t *ip_hdr;
    if ((buf->info & B_FROM_MASK) == B_FROM_IPV6_FWD) {
        // New paths leave IP header on for us to permit ICMP response;
        // note the pointer and strip now.
        ip_hdr = buffer_data_pointer(buf);
        buffer_data_strip_header(buf, buf->offset);
        buf->offset = 0;
    } else {
        // We came from cipv6_up (or...?) - we have no real IP headers
        ip_hdr = NULL;
    }

    uint16_t ip_len = buffer_data_length(buf);
    if (ip_len < 8) {
        return buffer_free(buf);
    }

    const uint8_t *udp_hdr = buffer_data_pointer(buf);

    buf->src_sa.port = read_be16(udp_hdr + 0);
    buf->dst_sa.port = read_be16(udp_hdr + 2);
    uint16_t udp_len = read_be16(udp_hdr + 4);

    buf = udp_rx_security_check(buf);
    if (!buf) {
        return NULL;
    }

    if (udp_len < 8 || udp_len > ip_len) {
        return buffer_free(buf);
    }

    // Set UDP length - may trim the buffer
    buffer_data_length_set(buf, udp_len);

    buf = udp_checksum_check(buf);
    if (!buf) {
        return buf;
    }

    // Remove UDP header
    buffer_data_pointer_set(buf, udp_hdr + 8);

    if (buf->dst_sa.port == 0) {
        tr_error("UDP port 0");
        protocol_stats_update(STATS_IP_RX_DROP, 1);
        return buffer_free(buf);
    }

    if (buf->dst_sa.port == UDP_PORT_ECHO && buf->src_sa.port != UDP_PORT_ECHO) {
        struct net_if *cur;
        tr_debug("UDP echo msg from %s", tr_ipv6(buf->src_sa.address));

        cur = buf->interface;

        if (addr_is_ipv6_multicast(buf->dst_sa.address)) {
            const uint8_t *ipv6_ptr;
            ipv6_ptr = addr_select_source(cur, buf->dst_sa.address, 0);
            if (!ipv6_ptr) {
                tr_debug("UDP Echo:No address");
                return buffer_free(buf);
            }
            memcpy(buf->dst_sa.address, buf->src_sa.address, 16);
            memcpy(buf->src_sa.address, ipv6_ptr, 16);
        } else {
            memswap(buf->dst_sa.address, buf->src_sa.address, 16);
        }
        buf->dst_sa.port = buf->src_sa.port;
        buf->src_sa.port = UDP_PORT_ECHO;

        buf->info = (buffer_info_t)(B_FROM_UDP | B_TO_UDP | B_DIR_DOWN);
        buf->options.hop_limit = UNICAST_HOP_LIMIT_DEFAULT;
        buf->options.traffic_class = 0;
        buf->IPHC_NH = 0;
        return buffer_turnaround(buf);
    }

    if (ip_hdr) {
        /* New path generates port unreachable here, using the real IP headers
         * that we know the position of thanks to buf->offset.
         *
         * Old path has socket_up make port unreachable itself, creating a
         * fake IP header.
         */
        if (!buf->socket) {
            buffer_socket_set(buf, socket_lookup_ipv6(IPV6_NH_UDP, &buf->dst_sa, &buf->src_sa, true));
        }
        if (!buf->socket) {
            // Reconstruct original IP packet
            buffer_data_pointer_set(buf, udp_hdr);
            buffer_data_length_set(buf, ip_len);
            buffer_data_pointer_set(buf, ip_hdr);
            return icmpv6_error(buf, NULL, ICMPV6_TYPE_ERROR_DESTINATION_UNREACH, ICMPV6_CODE_DST_UNREACH_PORT_UNREACH, 0);
        }
    }

    buf->options.type = (uint8_t) SOCKET_FAMILY_IPV6;
    buf->options.code = IPV6_NH_UDP;
    buf->info = (buffer_info_t)(B_FROM_UDP | B_TO_APP | B_DIR_UP);
    return buf;
}
