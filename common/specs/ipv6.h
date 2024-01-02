/*
 * Copyright (c) 2013-2017, Pelion and affiliates.
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
#ifndef SPECS_IPV6_H
#define SPECS_IPV6_H

#define IPV6_MIN_LINK_MTU   1280    /* All links can transfer 1280-octet IP packets */
#define IPV6_MIN_FRAG_MRU   1500    /* All hosts can receive 1500-octet fragmented datagrams */

/*
 * IPv6 header offsets
 */
#define IPV6_HDROFF_FLOW_LABEL      1
#define IPV6_HDROFF_PAYLOAD_LENGTH  4
#define IPV6_HDROFF_NH              6
#define IPV6_HDROFF_HOP_LIMIT       7
#define IPV6_HDROFF_SRC_ADDR        8
#define IPV6_HDROFF_DST_ADDR        24
#define IPV6_HDRLEN                 40

// RFC7045: "Assigned Internet Protocol Numbers"
// https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml#protocol-numbers-1
enum {
    IPV6_NH_HOP_BY_HOP = 0,
    // ...
    IPV6_NH_TCP        = 6,
    // ...
    IPV6_NH_UDP        = 17,
    // ...
    IPV6_NH_IPV6       = 41,
    IPV6_NH_SDRP       = 42,
    IPV6_NH_ROUTING    = 43,
    IPV6_NH_FRAGMENT   = 44,
    // ...
    IPV6_NH_AUTH       = 51,
    IPV6_NH_INLSP      = 52,
    IPV6_NH_SWIPE      = 53,
    IPV6_NH_NARP       = 54,
    IPV6_NH_MOBILITY   = 55,
    IPV6_NH_TLSP       = 56,
    IPV6_NH_SKIP       = 57,
    IPV6_NH_ICMPV6     = 58,
    IPV6_NH_NONE       = 59,
    IPV6_NH_DEST_OPT   = 60,
    // ...
    IPV6_NH_HIP        = 139,
    IPV6_NH_SHIM6      = 140,
};

// RFC8200: "Destination Options and Hop-by-Hop Options"
// See also RFC9008 "11.1. Option Type in RPL Option" for IPV6_OPTION_RPI.
// https://www.iana.org/assignments/ipv6-parameters/ipv6-parameters.xhtml#ipv6-parameters-2
enum {
    IPV6_OPTION_PAD1           = 0x00,
    IPV6_OPTION_PADN           = 0x01,
    // ...
    IPV6_OPTION_ROUTER_ALERT   = 0x05,
    // ...
    IPV6_OPTION_RPI            = 0x23,
    // ...
    IPV6_OPTION_RPI_DEPRECATED = 0x63,
    // ...
    IPV6_OPTION_MPL            = 0x6D,
    // ...
    IPV6_OPTION_MPL_EXP        = 0x7E,
};

/* Encoded bits in IPv6 Option numbers; action if unrecognised, and mutability */
#define IPV6_OPTION_ACTION_MASK             0xC0
#define IPV6_OPTION_ACTION_SKIP             0x00    /* ignore unrecognised */
#define IPV6_OPTION_ACTION_DISCARD          0x40    /* discard packet */
#define IPV6_OPTION_ACTION_ERROR            0x80    /* discard, and send ICMP Parameter Problem */
#define IPV6_OPTION_ACTION_ERROR_UNICAST    0xC0    /* discard, and send ICMP Parameter Problem if unicast dst */

#define IPV6_OPTION_CHANGE_MASK             0x20
#define IPV6_OPTION_CHANGE_DOES_NOT         0x00    /* does not change en-route */
#define IPV6_OPTION_CHANGE_MAY              0x20    /* may change en-route */

// RFC8200: "Routing Types"
// See also RFC 6554, "3. Format of the RPL Routing Header"
// https://www.iana.org/assignments/ipv6-parameters/ipv6-parameters.xhtml#ipv6-parameters-3
enum {
    IPV6_ROUTING_SOURCE_ROUTE = 0,
    IPV6_ROUTING_NIMROD       = 1,
    IPV6_ROUTING_TYPE2_RH     = 2,
    IPV6_ROUTING_RPL_SRH      = 3,
    IPV6_ROUTING_SRH          = 4,
};

// RFC7346: "IPv6 Multicast Address Scopes".
// https://www.iana.org/assignments/ipv6-multicast-addresses/ipv6-multicast-addresses.xhtml#ipv6-scope
enum {
    // 0x0 is reserved
    IPV6_SCOPE_INTERFACE_LOCAL           = 0x1,
    IPV6_SCOPE_LINK_LOCAL                = 0x2,
    IPV6_SCOPE_REALM_LOCAL               = 0x3,
    IPV6_SCOPE_ADMIN_LOCAL               = 0x4,
    IPV6_SCOPE_SITE_LOCAL                = 0x5,
    // 0x6 to 0x7 are unassigned
    IPV6_SCOPE_ORGANIZATION_LOCAL        = 0x8,
    // 0x9 to 0xD are unassigned
    IPV6_SCOPE_GLOBAL                    = 0xE,
};

/* Router Alert values (RFC 2711) */
#define IPV6_ROUTER_ALERT_MLD               0

#endif
